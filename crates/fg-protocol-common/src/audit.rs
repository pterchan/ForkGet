//! Durable write attempts and delivery acknowledgements.

use serde::{Deserialize, Serialize};

use crate::{DecisionRequest, TransactionOutcome, WireError};

pub const AUDIT_WITNESS_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    SqlTransaction,
    MongoCommand,
}

impl AuditMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SqlTransaction => "sql_transaction",
            Self::MongoCommand => "mongo_command",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAttemptContext {
    pub attempt_id: String,
    pub principal: String,
    pub session_id: String,
    pub native_session_id: u32,
    pub generation_id: i64,
    pub replay_job_id: Option<i64>,
    pub mode: AuditMode,
}

impl AuditAttemptContext {
    pub fn is_valid(&self) -> bool {
        let Some((session, ordinal)) = self.attempt_id.rsplit_once(':') else {
            return false;
        };
        let Some((epoch, serial)) = session.split_once(':') else {
            return false;
        };
        session == self.session_id
            && epoch.len() == 32
            && epoch
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && canonical_serial(serial)
            && canonical_serial(ordinal)
            && !self.principal.is_empty()
            && self.native_session_id > 0
            && self.generation_id > 0
            && self.replay_job_id.is_none_or(|id| id > 0)
    }
}

fn canonical_serial(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|id| id > 0 && value == id.to_string())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWitnessBinding {
    pub format_version: u16,
    pub deployment_id: String,
    pub branch_id: i64,
    pub generation_id: i64,
    pub storage_incarnation: String,
}

#[derive(Clone, Debug)]
pub struct AuditAttempt {
    context: AuditAttemptContext,
    witness: Option<NativeWitnessBinding>,
    armed_step: u32,
    intent_possible: bool,
    intent_confirmed: bool,
    possible_step: Option<u32>,
}

impl AuditAttempt {
    pub(crate) fn new(context: AuditAttemptContext) -> Self {
        Self {
            context,
            witness: None,
            armed_step: 0,
            intent_possible: false,
            intent_confirmed: false,
            possible_step: None,
        }
    }

    pub fn context(&self) -> &AuditAttemptContext {
        &self.context
    }

    pub fn witness(&self) -> Option<&NativeWitnessBinding> {
        self.witness.as_ref()
    }

    pub fn armed_step(&self) -> u32 {
        self.possible_step.unwrap_or(self.armed_step)
    }

    pub(crate) fn confirmed_step(&self) -> u32 {
        self.armed_step
    }

    pub(crate) fn mark_step_possible(&mut self) -> Result<(), WireError> {
        self.possible_step = Some(self.armed_step.checked_add(1).ok_or(WireError::Backend)?);
        Ok(())
    }

    pub fn is_prepared(&self) -> bool {
        self.intent_confirmed
    }

    pub fn intent_possible(&self) -> bool {
        self.intent_possible
    }

    pub(crate) fn mark_intent_possible(&mut self) {
        self.intent_possible = true;
    }

    pub(crate) fn accept_decision(
        &mut self,
        response: AuditedDecisionResponse,
    ) -> Result<Option<i64>, WireError> {
        if response.attempt_id != self.context.attempt_id
            || self
                .witness
                .as_ref()
                .is_some_and(|binding| Some(binding) != response.witness.as_ref())
        {
            return Err(WireError::Backend);
        }
        self.witness = response.witness;
        self.intent_confirmed = true;
        Ok(response.approval_id)
    }

    pub(crate) fn accept_step(&mut self, ack: &MongoStepAck) -> Result<(), WireError> {
        if ack.attempt_id != self.context.attempt_id
            || self.armed_step.checked_add(1) != Some(ack.armed_step)
        {
            return Err(WireError::Backend);
        }
        self.armed_step = ack.armed_step;
        self.possible_step = None;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedDecisionRequest {
    pub attempt: AuditAttemptContext,
    pub decision: DecisionRequest,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedDecisionResponse {
    pub attempt_id: String,
    pub approval_id: Option<i64>,
    pub witness: Option<NativeWitnessBinding>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MongoObservationState {
    NotSent,
    Acknowledged,
    AcknowledgedWithErrors,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MongoWriteObservation {
    pub state: MongoObservationState,
    pub matched: Option<u64>,
    pub modified: Option<u64>,
    pub inserted: Option<u64>,
    pub deleted: Option<u64>,
    pub upserted: Option<u64>,
    pub error_count: Option<u64>,
    pub native_code: Option<i32>,
}

impl MongoWriteObservation {
    pub fn outcome(&self, armed_step: u32) -> TransactionOutcome {
        match self.state {
            MongoObservationState::Unknown | MongoObservationState::AcknowledgedWithErrors => {
                TransactionOutcome::Unknown
            }
            MongoObservationState::NotSent if armed_step == 0 => TransactionOutcome::RolledBack,
            MongoObservationState::NotSent => TransactionOutcome::Unknown,
            MongoObservationState::Acknowledged => TransactionOutcome::Committed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditedOutcomeRequest {
    pub attempt: AuditAttemptContext,
    pub outcome: TransactionOutcome,
    pub armed_step: u32,
    pub mongo: Option<MongoWriteObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeAck {
    pub attempt_id: String,
    pub audit_event_id: i64,
    pub outcome: TransactionOutcome,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MongoStepRequest {
    pub attempt: AuditAttemptContext,
    pub expected_step: u32,
    pub previous: Option<MongoWriteObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MongoStepAck {
    pub attempt_id: String,
    pub armed_step: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatusRequest {
    pub attempt: AuditAttemptContext,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatus {
    pub ack: Option<OutcomeAck>,
    pub outcome: Option<AuditedOutcomeRequest>,
    pub resolution: Option<OutcomeAck>,
    pub retention_ack_event_id: Option<i64>,
    pub late_ack: Option<OutcomeAck>,
    pub late_outcome: Option<AuditedOutcomeRequest>,
    pub resolved: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteFenceRequest {
    pub attempt: AuditAttemptContext,
    pub policy_version: i64,
    pub effective_revision: i64,
    pub witness: Option<NativeWitnessBinding>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteFenceResponse {
    pub branch_id: i64,
    pub engine: String,
    pub context: WriteFenceRequest,
    pub expires_at: i64,
    pub lease_version: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_ids_require_canonical_positive_serials() {
        let session = format!("{}:7", "a".repeat(32));
        let mut context = AuditAttemptContext {
            attempt_id: format!("{session}:1"),
            session_id: session.clone(),
            principal: "alice".into(),
            native_session_id: 9,
            generation_id: 1,
            replay_job_id: None,
            mode: AuditMode::SqlTransaction,
        };
        assert!(context.is_valid());
        for ordinal in ["0", "01", "-1", "18446744073709551616", "1:2"] {
            context.attempt_id = format!("{session}:{ordinal}");
            assert!(!context.is_valid());
        }
    }
}
