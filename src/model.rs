use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct JsonEnvelope<T> {
    pub schema_version: u32,
    pub command: String,
    pub data: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub version: u32,
    pub workspace_dir: String,
    pub branch_strategy: String,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: 1,
            workspace_dir: "workspaces".to_string(),
            branch_strategy: "create_from_default".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub version: u32,
    pub repos: Vec<ManifestRepo>,
}

impl Default for ManifestFile {
    fn default() -> Self {
        Self {
            version: 1,
            repos: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRepo {
    pub name: String,
    pub path: String,
    pub default_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    pub workspaces: BTreeMap<String, WorkspaceState>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: 1,
            workspaces: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceState {
    pub branch: String,
    pub repos: BTreeMap<String, WorkspaceRepoState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRepoState {
    pub source_path: String,
    pub worktree_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoStatus {
    pub repo: String,
    pub source_path: String,
    pub worktree_path: String,
    pub exists: bool,
    pub branch: Option<String>,
    pub dirty: Option<bool>,
    pub staged_files: Option<u32>,
    pub unstaged_files: Option<u32>,
    pub untracked_files: Option<u32>,
    pub conflicts: Option<bool>,
    pub ahead: Option<u32>,
    pub behind: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceStatus {
    pub workspace: String,
    pub branch: String,
    pub repos: Vec<RepoStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSummary {
    pub workspaces_total: u32,
    pub workspaces_shown: u32,
    pub repos_total: u32,
    pub repos_shown: u32,
    pub dirty_repos_total: u32,
    pub dirty_repos_shown: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub changed_only: bool,
    pub summary: StatusSummary,
    pub workspaces: Vec<WorkspaceStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommitSummary {
    pub workspace: String,
    pub branch: String,
    pub dry_run: bool,
    pub planned_commits: Vec<String>,
    pub auto_staged: Vec<String>,
    pub committed: Vec<String>,
    pub skipped: Vec<String>,
    pub rolled_back: Vec<String>,
    pub rollback_failed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushRepoResult {
    pub repo: String,
    pub ahead: Option<u32>,
    pub behind: Option<u32>,
    pub pushed: bool,
    pub skipped_reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushSummary {
    pub workspace: String,
    pub branch: String,
    pub dry_run: bool,
    pub pushed: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
    pub repos: Vec<PushRepoResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorIssue {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub workspace: Option<String>,
    pub repo: Option<String>,
    pub path: Option<String>,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResponse {
    pub fix_mode: bool,
    pub fixes_applied: Vec<String>,
    pub issues: Vec<DoctorIssue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshSummary {
    pub check_only: bool,
    pub drift_detected: bool,
    pub repos_total: u32,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub updated: Vec<String>,
}
