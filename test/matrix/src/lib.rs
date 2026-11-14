//! Support-matrix consistency and evidence enforcement.
//!
//! The tracked manifest `test/support-matrix.json` is the CI input; the
//! public contract `doc/support-matrix.md` is the user-facing view. This
//! library keeps the two in agreement and refuses to let an implemented
//! capability exist without resolvable evidence files. Planned capabilities
//! stay visible without being counted as passed tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Enforcement failures; never silently downgrade a claim.
#[derive(Debug, thiserror::Error)]
pub enum MatrixError {
    #[error("{0}")]
    Load(String),
}

pub const MANIFEST_PATH: &str = "test/support-matrix.json";
pub const PUBLIC_MATRIX_PATH: &str = "doc/support-matrix.md";
pub const DEFAULT_CORPUS_DIR: &str = "test/differential/corpus";
pub const KNOWN_ENGINES: [&str; 4] = ["mysql", "postgresql", "tidb", "mongodb"];

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub updated_on: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
pub struct Capability {
    pub id: String,
    #[serde(default)]
    pub engines: Vec<String>,
    pub status: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub cases: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

impl Capability {
    pub fn is_implemented(&self) -> bool {
        self.status.starts_with("implemented")
    }
}

/// The corpus summary fg-matrix needs; extra fields in corpus files are
/// ignored on purpose so the runner schema can evolve independently.
#[derive(Debug, Deserialize)]
pub struct CorpusSummary {
    pub id: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub engines: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

pub struct Repository {
    root: PathBuf,
    pub manifest: Manifest,
    markdown_status: BTreeMap<String, String>,
    pub corpus: Vec<CorpusSummary>,
    corpus_sources: BTreeMap<String, PathBuf>,
}

impl Repository {
    pub fn load(root: &Path, corpus_dir: &Path) -> Result<Self, MatrixError> {
        let manifest_path = root.join(MANIFEST_PATH);
        let manifest_text = fs::read_to_string(&manifest_path)
            .map_err(|error| MatrixError::Load(format!("{}: {error}", manifest_path.display())))?;
        let manifest: Manifest = serde_json::from_str(&manifest_text)
            .map_err(|error| MatrixError::Load(format!("{}: {error}", manifest_path.display())))?;

        let markdown_path = root.join(PUBLIC_MATRIX_PATH);
        let markdown = fs::read_to_string(&markdown_path)
            .map_err(|error| MatrixError::Load(format!("{}: {error}", markdown_path.display())))?;
        let markdown_status = parse_markdown_statuses(&markdown);

        let (corpus, corpus_sources) = load_corpus_summaries(root, corpus_dir)?;

        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            markdown_status,
            corpus,
            corpus_sources,
        })
    }

    /// Full consistency and evidence check; every failure is reported.
    pub fn check(&self) -> Vec<String> {
        let mut failures = Vec::new();
        if self.manifest.schema_version != 1 {
            failures.push(format!(
                "manifest schema_version {} is not supported (expected 1)",
                self.manifest.schema_version
            ));
        }

        let mut seen = BTreeMap::new();
        for capability in &self.manifest.capabilities {
            if seen.insert(capability.id.as_str(), capability).is_some() {
                failures.push(format!("duplicate capability id '{}'", capability.id));
            }
        }

        for capability in &self.manifest.capabilities {
            let Some(markdown_status) = self.markdown_status.get(&capability.id) else {
                failures.push(format!(
                    "capability '{}' is missing from {}",
                    capability.id, PUBLIC_MATRIX_PATH
                ));
                continue;
            };
            let markdown_implemented = markdown_status.starts_with("Implemented");
            if markdown_implemented != capability.is_implemented() {
                failures.push(format!(
                    "capability '{}': manifest status '{}' disagrees with public status '{}'",
                    capability.id, capability.status, markdown_status
                ));
            }
        }
        for id in self.markdown_status.keys() {
            if !seen.contains_key(id.as_str()) {
                failures.push(format!(
                    "public matrix lists '{}' which the manifest does not track",
                    id
                ));
            }
        }

        for capability in &self.manifest.capabilities {
            if !capability.is_implemented() {
                continue;
            }
            if capability.cases.is_empty() {
                failures.push(format!(
                    "implemented capability '{}' lists no evidence cases",
                    capability.id
                ));
            }
            for file in &capability.files {
                if !self.root.join(file).is_file() {
                    failures.push(format!(
                        "implemented capability '{}' references missing file '{}'",
                        capability.id, file
                    ));
                }
            }
        }

        let known_ids: Vec<&str> = self
            .manifest
            .capabilities
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        let mut case_ids = BTreeMap::new();
        for case in &self.corpus {
            if case_ids.insert(case.id.as_str(), ()).is_some() {
                failures.push(format!("duplicate corpus case id '{}'", case.id));
            }
            if case.engines.is_empty() {
                failures.push(format!("corpus case '{}' declares no engines", case.id));
            }
            for engine in &case.engines {
                if !KNOWN_ENGINES.contains(&engine.as_str()) {
                    failures.push(format!(
                        "corpus case '{}' references unknown engine '{engine}'",
                        case.id
                    ));
                }
            }
            for capability in &case.capabilities {
                if !known_ids.contains(&capability.as_str()) {
                    failures.push(format!(
                        "corpus case '{}' references unknown capability '{capability}'",
                        case.id
                    ));
                }
            }
        }
        failures
    }

    /// Resolve a tag to its engine-specific corpus cases; unknown tags and
    /// empty selections are errors, never a pass.
    pub fn select_tag(&self, tag: &str) -> Result<Vec<(String, String)>, MatrixError> {
        let mut selection = Vec::new();
        for case in &self.corpus {
            if case.tags.iter().any(|candidate| candidate == tag) {
                for engine in &case.engines {
                    selection.push((engine.clone(), case.id.clone()));
                }
            }
        }
        if selection.is_empty() {
            return Err(MatrixError::Load(format!(
                "tag '{tag}' resolves to no corpus cases; this is a selection error, not a pass"
            )));
        }
        Ok(selection)
    }

    /// Resolve one capability: planned stays visible without evidence;
    /// implemented resolves to its tracked cases and files.
    pub fn resolve_capability(&self, id: &str) -> Result<CapabilityView<'_>, MatrixError> {
        let capability = self
            .manifest
            .capabilities
            .iter()
            .find(|capability| capability.id == id)
            .ok_or_else(|| MatrixError::Load(format!("unknown capability id '{id}'")))?;
        if !capability.is_implemented() {
            return Ok(CapabilityView {
                capability,
                planned: true,
            });
        }
        if capability.cases.is_empty() {
            return Err(MatrixError::Load(format!(
                "implemented capability '{id}' has an empty case set"
            )));
        }
        Ok(CapabilityView {
            capability,
            planned: false,
        })
    }

    pub fn corpus_source(&self, case_id: &str) -> Option<&Path> {
        self.corpus_sources.get(case_id).map(PathBuf::as_path)
    }
}

pub struct CapabilityView<'a> {
    pub capability: &'a Capability,
    pub planned: bool,
}

/// Extract `| \`id\` | Status text | ...` rows from the capability table in
/// the public markdown. Only the table whose header names "Capability ID" is
/// parsed; other tables (for example the error registry) are not capabilities.
fn parse_markdown_statuses(markdown: &str) -> BTreeMap<String, String> {
    let mut statuses = BTreeMap::new();
    let mut in_capability_table = false;
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('|') {
            in_capability_table = false;
            continue;
        }
        if trimmed.contains("Capability ID") {
            in_capability_table = true;
            continue;
        }
        if !in_capability_table {
            continue;
        }
        let cells: Vec<&str> = trimmed.split('|').collect();
        if cells.len() < 3 {
            continue;
        }
        let id = cells[1].trim().trim_matches('`');
        let status = cells[2].trim();
        if id.is_empty() || status.is_empty() || status.starts_with('-') {
            continue;
        }
        statuses.insert(id.to_string(), status.to_string());
    }
    statuses
}

fn load_corpus_summaries(
    root: &Path,
    corpus_dir: &Path,
) -> Result<(Vec<CorpusSummary>, BTreeMap<String, PathBuf>), MatrixError> {
    let directory = root.join(corpus_dir);
    let entries = fs::read_dir(&directory)
        .map_err(|error| MatrixError::Load(format!("{}: {error}", directory.display())))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| MatrixError::Load(format!("{}: {error}", directory.display())))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(MatrixError::Load(format!(
            "no corpus files under {}",
            directory.display()
        )));
    }
    let mut summaries = Vec::new();
    let mut sources = BTreeMap::new();
    for path in paths {
        let text = fs::read_to_string(&path)
            .map_err(|error| MatrixError::Load(format!("{}: {error}", path.display())))?;
        let parsed: Vec<CorpusSummary> = serde_json::from_str(&text)
            .map_err(|error| MatrixError::Load(format!("{}: {error}", path.display())))?;
        for summary in parsed {
            sources.insert(summary.id.clone(), path.clone());
            summaries.push(summary);
        }
    }
    Ok((summaries, sources))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type TestResult = Result<(), MatrixError>;

    const MANIFEST: &str = r#"{
        "schema_version": 1,
        "capabilities": [
            {
                "id": "relation.postgres",
                "engines": ["postgresql"],
                "status": "implemented_library",
                "cases": ["postgres_overlay_matches_golden_sql"],
                "files": ["crates/fg-rewrite/tests/visible_relation.rs"]
            },
            {
                "id": "sql.parser",
                "engines": ["mysql", "postgresql"],
                "status": "planned"
            }
        ]
    }"#;

    const MARKDOWN: &str = "# Support matrix\n\n| Capability ID | Current status | Scope |\n|---|---|---|\n| `relation.postgres` | Implemented library; local | renderer |\n| `sql.parser` | Planned | parser |\n";

    fn io(message: &str) -> MatrixError {
        MatrixError::Load(message.to_string())
    }

    fn write_file(path: &Path, content: &str) -> Result<(), MatrixError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| io(&format!("{}: {error}", path.display())))?;
        }
        fs::write(path, content).map_err(|error| io(&format!("{}: {error}", path.display())))
    }

    fn synthetic_repository(directory: &Path) -> Result<Repository, MatrixError> {
        write_file(
            &directory.join("crates/fg-rewrite/tests/visible_relation.rs"),
            "// evidence\n",
        )?;
        write_file(
            &directory.join("corpus/smoke.json"),
            r#"[{"id": "select_one", "tags": ["smoke"], "engines": ["mysql"], "capabilities": []}]"#,
        )?;
        write_file(&directory.join(MANIFEST_PATH), MANIFEST)?;
        write_file(&directory.join(PUBLIC_MATRIX_PATH), MARKDOWN)?;
        Repository::load(directory, Path::new("corpus"))
    }

    fn failures_containing(repository: &Repository, fragment: &str) -> Vec<String> {
        repository
            .check()
            .into_iter()
            .filter(|failure| failure.contains(fragment))
            .collect()
    }

    #[test]
    fn consistent_repository_passes() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let repository = synthetic_repository(temporary.path())?;
        assert!(
            repository.check().is_empty(),
            "failures: {:?}",
            repository.check()
        );
        Ok(())
    }

    #[test]
    fn missing_evidence_file_fails_the_check() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let directory = temporary.path().to_path_buf();
        let repository = synthetic_repository(&directory)?;
        fs::remove_file(directory.join("crates/fg-rewrite/tests/visible_relation.rs"))
            .map_err(|error| io(&error.to_string()))?;
        let failures = failures_containing(&repository, "missing file");
        assert_eq!(failures.len(), 1, "failures: {:?}", repository.check());
        Ok(())
    }

    #[test]
    fn implemented_capability_without_cases_fails() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let directory = temporary.path().to_path_buf();
        synthetic_repository(&directory)?;
        let broken = MANIFEST.replace(
            "\"cases\": [\"postgres_overlay_matches_golden_sql\"],",
            "\"cases\": [],",
        );
        write_file(&directory.join(MANIFEST_PATH), &broken)?;
        let repository = Repository::load(&directory, Path::new("corpus"))?;
        let failures = failures_containing(&repository, "no evidence cases");
        assert_eq!(failures.len(), 1, "failures: {:?}", repository.check());
        Ok(())
    }

    #[test]
    fn corpus_reference_to_unknown_capability_fails() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let directory = temporary.path().to_path_buf();
        synthetic_repository(&directory)?;
        write_file(
            &directory.join("corpus/smoke.json"),
            r#"[{"id": "select_one", "tags": ["smoke"], "engines": ["mysql"], "capabilities": ["read.overlay"]}]"#,
        )?;
        let repository = Repository::load(&directory, Path::new("corpus"))?;
        let failures = failures_containing(&repository, "unknown capability 'read.overlay'");
        assert_eq!(failures.len(), 1, "failures: {:?}", repository.check());
        Ok(())
    }

    #[test]
    fn public_status_disagreement_fails() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let directory = temporary.path().to_path_buf();
        synthetic_repository(&directory)?;
        let flipped = MARKDOWN.replace("Implemented library; local", "Planned; something else");
        write_file(&directory.join(PUBLIC_MATRIX_PATH), &flipped)?;
        let repository = Repository::load(&directory, Path::new("corpus"))?;
        let failures = failures_containing(&repository, "disagrees with public status");
        assert_eq!(failures.len(), 1, "failures: {:?}", repository.check());
        Ok(())
    }

    #[test]
    fn planned_capability_stays_visible_without_evidence() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let repository = synthetic_repository(temporary.path())?;
        let view = repository.resolve_capability("sql.parser")?;
        assert!(view.planned, "planned capability must stay visible");
        assert!(view.capability.files.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_tag_selection_is_an_error() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let repository = synthetic_repository(temporary.path())?;
        let selection = repository.select_tag("does-not-exist");
        assert!(
            matches!(&selection, Err(MatrixError::Load(message)) if message.contains("resolves to no corpus cases")),
            "selection: {selection:?}"
        );
        Ok(())
    }

    #[test]
    fn known_tag_resolves_engine_specific_cases() -> TestResult {
        let temporary = tempfile::tempdir().map_err(|error| io(&error.to_string()))?;
        let repository = synthetic_repository(temporary.path())?;
        let selection = repository.select_tag("smoke")?;
        assert_eq!(selection, [("mysql".to_string(), "select_one".to_string())]);
        Ok(())
    }

    #[test]
    fn real_repository_is_consistent() -> TestResult {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let repository = Repository::load(&root, Path::new(DEFAULT_CORPUS_DIR))?;
        let failures = repository.check();
        assert!(failures.is_empty(), "failures: {failures:?}");
        Ok(())
    }
}
