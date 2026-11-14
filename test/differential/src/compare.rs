//! Comparator with explicit fault-detection semantics.

use crate::corpus::{Expectation, RowOrder};
use crate::observe::{CanonValue, Observation};

/// A detected difference between the two sides (or between a side and the
/// expectation). Details name the side and the nature of the difference.
#[derive(Clone, Debug)]
pub struct Mismatch {
    pub detail: String,
}

impl Mismatch {
    fn new(detail: String) -> Self {
        Self { detail }
    }
}

/// Per-step comparison outcome used by the runner's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Passed,
    Failed,
}

/// Compare the reference and candidate observations of one step against the
/// expectation. Every deliberately wrong observation must be detected; nothing
/// is normalized away.
pub fn compare_step(
    step_index: usize,
    expectation: &Expectation,
    reference: &Observation,
    candidate: &Observation,
) -> Result<StepOutcome, Mismatch> {
    match expectation {
        Expectation::ProxyRefusal { .. } => Err(Mismatch::new(
            "proxy refusal requires reference-vs-proxy mode".into(),
        )),
        Expectation::Rows { order } => {
            let (reference_rows, candidate_rows) = match (reference, candidate) {
                (
                    Observation::Rows {
                        columns: reference_columns,
                        rows: reference_rows,
                    },
                    Observation::Rows {
                        columns: candidate_columns,
                        rows: candidate_rows,
                    },
                ) => {
                    compare_columns(step_index, reference_columns, candidate_columns)?;
                    (reference_rows, candidate_rows)
                }
                _ => {
                    return Err(Mismatch::new(format!(
                        "step {step_index}: expected rows; reference produced {}, candidate produced {}",
                        reference.describe(),
                        candidate.describe()
                    )));
                }
            };
            compare_rows(step_index, *order, reference_rows, candidate_rows)
        }
        Expectation::Affected { count } => match (reference, candidate) {
            (Observation::Affected(reference_count), Observation::Affected(candidate_count)) => {
                if reference_count == candidate_count && reference_count == count {
                    Ok(StepOutcome::Passed)
                } else {
                    Err(Mismatch::new(format!(
                        "step {step_index}: affected rows differ: expected {count}, reference {reference_count}, candidate {candidate_count}"
                    )))
                }
            }
            _ => Err(Mismatch::new(format!(
                "step {step_index}: expected affected count {count}; reference produced {}, candidate produced {}",
                reference.describe(),
                candidate.describe()
            ))),
        },
        Expectation::Error { class } => match (reference, candidate) {
            (
                Observation::Error {
                    class: reference_class,
                    ..
                },
                Observation::Error {
                    class: candidate_class,
                    ..
                },
            ) => {
                if reference_class != class || candidate_class != class {
                    return Err(Mismatch::new(format!(
                        "step {step_index}: error class differs: expected {class}, reference {reference_class}, candidate {candidate_class}"
                    )));
                }
                Ok(StepOutcome::Passed)
            }
            _ => Err(Mismatch::new(format!(
                "step {step_index}: expected error class {class}; reference produced {}, candidate produced {}",
                reference.describe(),
                candidate.describe()
            ))),
        },
    }
}

fn compare_columns(
    step_index: usize,
    reference: &[crate::observe::ColumnMeta],
    candidate: &[crate::observe::ColumnMeta],
) -> Result<(), Mismatch> {
    // With an empty result set both engines return no rows and therefore no
    // column metadata through this harness; that limitation is documented in
    // the package README and affects both sides identically.
    if reference.is_empty() && candidate.is_empty() {
        return Ok(());
    }
    let names = |columns: &[crate::observe::ColumnMeta]| {
        columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if reference.len() != candidate.len()
        || reference
            .iter()
            .zip(candidate)
            .any(|(left, right)| left.name != right.name)
    {
        return Err(Mismatch::new(format!(
            "step {step_index}: column names differ: reference [{}], candidate [{}]",
            names(reference),
            names(candidate)
        )));
    }
    if reference
        .iter()
        .zip(candidate)
        .any(|(left, right)| left.type_name != right.type_name)
    {
        let mut differences = Vec::new();
        for (left, right) in reference.iter().zip(candidate) {
            if left.type_name != right.type_name {
                differences.push(format!(
                    "{}: {} vs {}",
                    left.name, left.type_name, right.type_name
                ));
            }
        }
        return Err(Mismatch::new(format!(
            "step {step_index}: column types differ: {}",
            differences.join("; ")
        )));
    }
    Ok(())
}

fn compare_rows(
    step_index: usize,
    order: RowOrder,
    reference: &[Vec<CanonValue>],
    candidate: &[Vec<CanonValue>],
) -> Result<StepOutcome, Mismatch> {
    let equal = match order {
        RowOrder::Total => reference == candidate,
        RowOrder::Multiset => {
            let mut reference_keys = reference
                .iter()
                .map(|row| canonical_row_key(row))
                .collect::<Vec<_>>();
            let mut candidate_keys = candidate
                .iter()
                .map(|row| canonical_row_key(row))
                .collect::<Vec<_>>();
            reference_keys.sort();
            candidate_keys.sort();
            reference_keys == candidate_keys
        }
    };
    if equal {
        Ok(StepOutcome::Passed)
    } else {
        Err(Mismatch::new(format!(
            "step {step_index}: rows differ (order {:?}): reference {} rows, candidate {} rows; first difference at row {}",
            order,
            reference.len(),
            candidate.len(),
            first_difference(reference, candidate)
        )))
    }
}

fn first_difference(reference: &[Vec<CanonValue>], candidate: &[Vec<CanonValue>]) -> usize {
    for index in 0..reference.len().max(candidate.len()) {
        let left = reference.get(index);
        let right = candidate.get(index);
        if left != right {
            return index;
        }
    }
    reference.len()
}

/// Length-prefixed canonical encoding: NULL stays distinct from any bytes and
/// boundaries between columns are unambiguous.
fn canonical_row_key(row: &[CanonValue]) -> Vec<u8> {
    let mut key = Vec::new();
    for value in row {
        match value {
            CanonValue::Null => key.extend_from_slice(&[0]),
            CanonValue::Bytes(bytes) => {
                key.extend_from_slice(&[1]);
                key.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                key.extend_from_slice(bytes);
            }
        }
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::ColumnMeta;

    type TestResult = Result<(), Mismatch>;

    /// Assert that a comparison failed and name the expected detail fragment.
    /// The `Ok` arm asserts on a condition the caller already disproved, so an
    /// unexpected pass still fails the test without banned macros.
    fn assert_mismatch(result: Result<StepOutcome, Mismatch>, expected_detail: &str) {
        match result {
            Err(mismatch) => {
                assert!(
                    mismatch.detail.contains(expected_detail),
                    "detail: {}",
                    mismatch.detail
                )
            }
            Ok(_) => assert!(
                result.is_err(),
                "expected a mismatch containing {expected_detail}"
            ),
        }
    }

    fn column(name: &str) -> ColumnMeta {
        ColumnMeta {
            name: name.to_string(),
            type_name: "BIGINT".to_string(),
        }
    }

    fn text_column(name: &str) -> ColumnMeta {
        ColumnMeta {
            name: name.to_string(),
            type_name: "VARCHAR".to_string(),
        }
    }

    fn text(value: &str) -> CanonValue {
        CanonValue::Bytes(value.as_bytes().to_vec())
    }

    fn rows(columns: Vec<ColumnMeta>, rows: Vec<Vec<CanonValue>>) -> Observation {
        Observation::Rows { columns, rows }
    }

    #[test]
    fn equal_observations_pass() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Total,
        };
        let observation = rows(vec![column("id")], vec![vec![text("1")], vec![text("2")]]);
        let outcome = compare_step(
            0,
            &expectation,
            &observation,
            &rows(vec![column("id")], vec![vec![text("1")], vec![text("2")]]),
        )?;
        assert_eq!(outcome, StepOutcome::Passed);
        Ok(())
    }

    #[test]
    fn unequal_values_are_detected() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Total,
        };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &rows(vec![column("id")], vec![vec![text("1")]]),
                &rows(vec![column("id")], vec![vec![text("2")]]),
            ),
            "rows differ",
        );
        Ok(())
    }

    #[test]
    fn null_versus_value_is_detected() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Total,
        };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &rows(vec![column("id")], vec![vec![text("10.00")]]),
                &rows(vec![column("id")], vec![vec![CanonValue::Null]]),
            ),
            "rows differ",
        );
        Ok(())
    }

    #[test]
    fn duplicate_count_differences_are_detected() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Multiset,
        };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &rows(
                    vec![column("amount")],
                    vec![vec![text("10")], vec![text("10")]],
                ),
                &rows(vec![column("amount")], vec![vec![text("10")]]),
            ),
            "reference 2 rows, candidate 1 rows",
        );
        Ok(())
    }

    #[test]
    fn multiset_order_differences_pass() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Multiset,
        };
        let outcome = compare_step(
            0,
            &expectation,
            &rows(
                vec![column("amount")],
                vec![vec![text("10")], vec![text("20")]],
            ),
            &rows(
                vec![column("amount")],
                vec![vec![text("20")], vec![text("10")]],
            ),
        )?;
        assert_eq!(outcome, StepOutcome::Passed);
        Ok(())
    }

    #[test]
    fn incorrect_error_classes_are_detected() -> TestResult {
        let expectation = Expectation::Error {
            class: "unique_violation".to_string(),
        };
        let reference = Observation::Error {
            class: "unique_violation".to_string(),
            code: Some("1062".to_string()),
            message: "Duplicate entry".to_string(),
        };
        let candidate = Observation::Error {
            class: "not_null_violation".to_string(),
            code: Some("1048".to_string()),
            message: "Column cannot be null".to_string(),
        };
        assert_mismatch(
            compare_step(0, &expectation, &reference, &candidate),
            "expected unique_violation",
        );
        Ok(())
    }

    #[test]
    fn expected_error_with_success_is_detected() -> TestResult {
        let expectation = Expectation::Error {
            class: "unique_violation".to_string(),
        };
        let success = rows(vec![column("id")], vec![]);
        assert_mismatch(
            compare_step(0, &expectation, &success, &success),
            "expected error class unique_violation",
        );
        Ok(())
    }

    #[test]
    fn wrong_affected_counts_are_detected() -> TestResult {
        let expectation = Expectation::Affected { count: 3 };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &Observation::Affected(3),
                &Observation::Affected(5),
            ),
            "expected 3, reference 3, candidate 5",
        );
        Ok(())
    }

    #[test]
    fn column_name_differences_are_detected() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Total,
        };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &rows(
                    vec![column("id"), text_column("note")],
                    vec![vec![text("1"), text("x")]],
                ),
                &rows(
                    vec![column("id"), text_column("label")],
                    vec![vec![text("1"), text("x")]],
                ),
            ),
            "column names differ",
        );
        Ok(())
    }

    #[test]
    fn column_type_differences_are_detected() -> TestResult {
        let expectation = Expectation::Rows {
            order: RowOrder::Total,
        };
        assert_mismatch(
            compare_step(
                0,
                &expectation,
                &rows(vec![text_column("note")], vec![vec![text("x")]]),
                &rows(vec![column("note")], vec![vec![text("x")]]),
            ),
            "column types differ",
        );
        Ok(())
    }
}
