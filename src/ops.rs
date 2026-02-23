use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Serialize;

use crate::{
    discovery,
    errors::{self, EXIT_CHECK_FAILED, EXIT_GIT},
    git,
    model::{
        CommitSummary, ConfigFile, DoctorIssue, DoctorResponse, JSON_SCHEMA_VERSION, JsonEnvelope,
        ManifestFile, PushRepoResult, PushSummary, RefreshSummary, RepoStatus, StateFile,
        StatusResponse, StatusSummary, WorkspaceRepoState, WorkspaceState, WorkspaceStatus,
    },
    storage::{
        AppPaths, assert_workspace_name_valid, load_config, load_manifest, load_state,
        resolve_existing_workspace, save_config, save_manifest, save_state,
    },
};

struct Loaded {
    paths: AppPaths,
    config: ConfigFile,
    manifest: ManifestFile,
    state: StateFile,
}

#[derive(Debug, Default, Clone)]
struct CopyRules {
    include_set: Option<GlobSet>,
    include_patterns: Vec<String>,
    exclude_set: Option<GlobSet>,
}

fn load(root: &Path) -> Result<Loaded> {
    let paths = AppPaths::from_root(root)?;
    paths.ensure_exists()?;

    Ok(Loaded {
        config: load_config(&paths)?,
        manifest: load_manifest(&paths)?,
        state: load_state(&paths)?,
        paths,
    })
}

fn print_json<T: Serialize>(command: &str, data: T) -> Result<()> {
    let envelope = JsonEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        command: command.to_string(),
        data,
    };
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

pub fn init(root: &Path) -> Result<()> {
    let paths = AppPaths::from_root(root)?;
    if paths.is_initialized() {
        bail!(
            "{} already contains initialized metadata at {}",
            paths.root.display(),
            paths.etz_dir.display()
        );
    }

    paths.initialize()?;

    let discovered = discovery::discover_repos(&paths.root)?;
    let manifest = ManifestFile {
        version: 1,
        repos: discovery::to_manifest_entries(&paths.root, &discovered),
    };

    let config = ConfigFile::default();
    let state = StateFile::default();

    fs::create_dir_all(paths.workspaces_dir(&config)).with_context(|| {
        format!(
            "failed to create {}",
            paths.workspaces_dir(&config).display()
        )
    })?;

    save_config(&paths, &config)?;
    save_manifest(&paths, &manifest)?;
    save_state(&paths, &state)?;

    println!(
        "Initialized etz in {} ({} repos discovered)",
        paths.etz_dir.display(),
        manifest.repos.len()
    );

    Ok(())
}

pub fn refresh_manifest(root: &Path, check_only: bool, json: bool) -> Result<()> {
    let loaded = load(root)?;
    let discovered = discovery::discover_repos(&loaded.paths.root)?;
    let refreshed = ManifestFile {
        version: loaded.manifest.version.max(1),
        repos: discovery::to_manifest_entries(&loaded.paths.root, &discovered),
    };

    let old_by_name: BTreeMap<&str, (&str, &str)> = loaded
        .manifest
        .repos
        .iter()
        .map(|repo| {
            (
                repo.name.as_str(),
                (repo.path.as_str(), repo.default_branch.as_str()),
            )
        })
        .collect();
    let new_by_name: BTreeMap<&str, (&str, &str)> = refreshed
        .repos
        .iter()
        .map(|repo| {
            (
                repo.name.as_str(),
                (repo.path.as_str(), repo.default_branch.as_str()),
            )
        })
        .collect();

    let mut added = Vec::<String>::new();
    let mut removed = Vec::<String>::new();
    let mut updated = Vec::<String>::new();

    for (name, _) in &new_by_name {
        if !old_by_name.contains_key(name) {
            added.push((*name).to_string());
        }
    }
    for (name, _) in &old_by_name {
        if !new_by_name.contains_key(name) {
            removed.push((*name).to_string());
        }
    }
    for (name, (new_path, new_default)) in &new_by_name {
        if let Some((old_path, old_default)) = old_by_name.get(name)
            && (old_path != new_path || old_default != new_default)
        {
            updated.push((*name).to_string());
        }
    }

    let drift_detected = !(added.is_empty() && removed.is_empty() && updated.is_empty());
    let summary = RefreshSummary {
        check_only,
        drift_detected,
        repos_total: refreshed.repos.len() as u32,
        added: added.clone(),
        removed: removed.clone(),
        updated: updated.clone(),
    };

    if !check_only {
        save_manifest(&loaded.paths, &refreshed)?;
    }

    if json {
        print_json("refresh", summary)?;
    } else if check_only {
        println!(
            "Manifest check: repos={} added={} removed={} updated={}",
            refreshed.repos.len(),
            added.len(),
            removed.len(),
            updated.len()
        );
        if !added.is_empty() {
            println!("Would add repos: {}", added.join(", "));
        }
        if !removed.is_empty() {
            println!("Would remove repos: {}", removed.join(", "));
        }
        if !updated.is_empty() {
            println!("Would update repos: {}", updated.join(", "));
        }
    } else {
        println!(
            "Refreshed manifest: repos={} added={} removed={} updated={}",
            refreshed.repos.len(),
            added.len(),
            removed.len(),
            updated.len()
        );
        if !added.is_empty() {
            println!("Added repos: {}", added.join(", "));
        }
        if !removed.is_empty() {
            println!("Removed repos: {}", removed.join(", "));
        }
        if !updated.is_empty() {
            println!("Updated repos: {}", updated.join(", "));
        }
    }

    if check_only && drift_detected {
        return errors::err(
            EXIT_CHECK_FAILED,
            "manifest drift detected; run `etz refresh` to apply updates",
        );
    }

    Ok(())
}

pub fn add_workspace(
    root: &Path,
    workspace: &str,
    branch: &str,
    from_current: bool,
    copy_root: bool,
) -> Result<()> {
    assert_workspace_name_valid(workspace)?;
    if branch.trim().is_empty() {
        bail!("branch cannot be empty");
    }

    let mut loaded = load(root)?;

    if loaded.state.workspaces.contains_key(workspace) {
        bail!("workspace '{}' already exists", workspace);
    }

    let workspace_root = loaded.paths.workspace_dir(&loaded.config, workspace);
    if workspace_root.exists() {
        bail!(
            "workspace directory {} already exists",
            workspace_root.display()
        );
    }

    fs::create_dir_all(&workspace_root)
        .with_context(|| format!("failed to create {}", workspace_root.display()))?;

    let copy_rules = load_copy_rules(&loaded.paths.root)?;

    if copy_root {
        if let Err(err) = copy_non_repo_root_entries(
            &loaded.paths.root,
            &workspace_root,
            &loaded.manifest,
            &copy_rules,
        ) {
            fs::remove_dir_all(&workspace_root).ok();
            bail!(
                "failed copying root files into workspace '{}' at {}: {}",
                workspace,
                workspace_root.display(),
                err
            );
        }
    }

    let mut created_worktrees: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    let mut workspace_repos = BTreeMap::new();

    for repo in &loaded.manifest.repos {
        let source_path = loaded.paths.root.join(&repo.path);
        if !git::is_git_repo(&source_path) {
            let rollback_errors = rollback_added_worktrees(&created_worktrees);
            fs::remove_dir_all(&workspace_root).ok();
            if rollback_errors.is_empty() {
                bail!(
                    "source repo '{}' is missing or invalid at {}",
                    repo.name,
                    source_path.display()
                );
            }
            bail!(
                "source repo '{}' is missing or invalid at {} (rollback had {} issue(s))",
                repo.name,
                source_path.display(),
                rollback_errors.len()
            );
        }

        let base_branch = if from_current {
            git::current_branch(&source_path)?
                .ok_or_else(|| anyhow!(
                    "repo '{}' is in detached HEAD; cannot use --from-current",
                    repo.name
                ))?
        } else {
            repo.default_branch.clone()
        };

        if let Err(err) = ensure_workspace_branch(&source_path, branch, &base_branch) {
            let rollback_errors = rollback_added_worktrees(&created_worktrees);
            fs::remove_dir_all(&workspace_root).ok();
            if rollback_errors.is_empty() {
                bail!(
                    "failed preparing branch for repo '{}' at {}: {}",
                    repo.name,
                    source_path.display(),
                    err
                );
            }
            bail!(
                "failed preparing branch for repo '{}' at {}: {} (rollback had {} issue(s))",
                repo.name,
                source_path.display(),
                err,
                rollback_errors.len()
            );
        }

        let worktree_path = workspace_root.join(&repo.name);
        if worktree_path.exists() {
            let rollback_errors = rollback_added_worktrees(&created_worktrees);
            fs::remove_dir_all(&workspace_root).ok();
            if rollback_errors.is_empty() {
                bail!(
                    "target path already exists for repo '{}' at {}",
                    repo.name,
                    worktree_path.display()
                );
            }
            bail!(
                "target path already exists for repo '{}' at {} (rollback had {} issue(s))",
                repo.name,
                worktree_path.display(),
                rollback_errors.len()
            );
        }

        let add_out = match git::git(
            &source_path,
            [
                "worktree",
                "add",
                worktree_path.to_string_lossy().as_ref(),
                branch,
            ],
        ) {
            Ok(out) => out,
            Err(err) => {
                let rollback_errors = rollback_added_worktrees(&created_worktrees);
                fs::remove_dir_all(&workspace_root).ok();
                if rollback_errors.is_empty() {
                    bail!(
                        "failed invoking git worktree add for repo '{}' at {}: {}",
                        repo.name,
                        worktree_path.display(),
                        err
                    );
                }
                bail!(
                    "failed invoking git worktree add for repo '{}' at {}: {} (rollback had {} issue(s))",
                    repo.name,
                    worktree_path.display(),
                    err,
                    rollback_errors.len()
                );
            }
        };
        if !add_out.success {
            let rollback_errors = rollback_added_worktrees(&created_worktrees);
            fs::remove_dir_all(&workspace_root).ok();
            let detail = if add_out.stderr.is_empty() {
                "unknown git error".to_string()
            } else {
                add_out.stderr
            };
            if rollback_errors.is_empty() {
                bail!(
                    "failed adding worktree for repo '{}' at {}: {}",
                    repo.name,
                    worktree_path.display(),
                    detail
                );
            }
            bail!(
                "failed adding worktree for repo '{}' at {}: {} (rollback had {} issue(s))",
                repo.name,
                worktree_path.display(),
                detail,
                rollback_errors.len()
            );
        }

        created_worktrees.push((
            repo.name.clone(),
            source_path.clone(),
            worktree_path.clone(),
        ));

        workspace_repos.insert(
            repo.name.clone(),
            WorkspaceRepoState {
                source_path: source_path.to_string_lossy().to_string(),
                worktree_path: worktree_path.to_string_lossy().to_string(),
            },
        );
    }

    loaded.state.workspaces.insert(
        workspace.to_string(),
        WorkspaceState {
            branch: branch.to_string(),
            repos: workspace_repos,
        },
    );

    save_state(&loaded.paths, &loaded.state)?;
    println!(
        "Added workspace '{}' on branch '{}' with {} repos",
        workspace,
        branch,
        loaded.manifest.repos.len()
    );

    Ok(())
}

fn rollback_added_worktrees(created_worktrees: &[(String, PathBuf, PathBuf)]) -> Vec<String> {
    let mut errors = Vec::new();

    for (repo_name, source_path, worktree_path) in created_worktrees.iter().rev() {
        let out = git::git(
            source_path,
            [
                "worktree",
                "remove",
                "--force",
                worktree_path.to_string_lossy().as_ref(),
            ],
        );
        match out {
            Ok(result) if result.success => {}
            Ok(result) => {
                errors.push(format!(
                    "rollback remove failed for '{}': {}",
                    repo_name, result.stderr
                ));
            }
            Err(err) => {
                errors.push(format!("rollback remove failed for '{}': {err}", repo_name));
            }
        }

        if worktree_path.exists() {
            fs::remove_dir_all(worktree_path).ok();
        }
    }

    errors
}

fn ensure_workspace_branch(repo_path: &Path, branch: &str, default_branch: &str) -> Result<()> {
    if git::branch_exists_local(repo_path, branch)? {
        return Ok(());
    }

    if git::branch_exists_remote(repo_path, branch)? {
        let remote_ref = format!("origin/{branch}");
        git::git_ok(
            repo_path,
            ["branch", "--track", branch, remote_ref.as_str()],
        )?;
        return Ok(());
    }

    if !git::branch_exists_local(repo_path, default_branch)? {
        if git::branch_exists_remote(repo_path, default_branch)? {
            let remote_ref = format!("origin/{default_branch}");
            git::git_ok(
                repo_path,
                ["branch", "--track", default_branch, remote_ref.as_str()],
            )?;
        } else {
            let head = git::git_ok(repo_path, ["rev-parse", "HEAD"])?;
            git::git_ok(repo_path, ["branch", default_branch, head.trim()])?;
        }
    }

    git::git_ok(repo_path, ["branch", branch, default_branch])?;
    Ok(())
}

fn load_copy_rules(root: &Path) -> Result<CopyRules> {
    let include_patterns = read_patterns(&root.join(".etzcopy"))?;
    let exclude_patterns = read_patterns(&root.join(".etzignore"))?;

    let include_set = build_glob_set(&include_patterns)?;
    let exclude_set = build_glob_set(&exclude_patterns)?;

    Ok(CopyRules {
        include_set,
        include_patterns,
        exclude_set,
    })
}

fn read_patterns(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut patterns = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let normalized = trimmed
            .trim_start_matches("./")
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if normalized.is_empty() {
            continue;
        }
        patterns.push(normalized);
    }

    Ok(patterns)
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob =
            Glob::new(pattern).with_context(|| format!("invalid glob pattern '{}'", pattern))?;
        builder.add(glob);
    }

    let set = builder.build().context("failed to build copy glob set")?;
    Ok(Some(set))
}

fn normalize_rel_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn matches_or_has_descendant_match(
    set: &GlobSet,
    patterns: &[String],
    rel: &str,
    is_dir: bool,
) -> bool {
    if set.is_match(rel) {
        return true;
    }
    if !is_dir {
        return false;
    }

    let probe_child = format!("{rel}/__etz_probe__");
    if set.is_match(&probe_child) {
        return true;
    }

    let prefix = format!("{rel}/");
    patterns.iter().any(|pattern| pattern.starts_with(&prefix))
}

fn should_copy_relative(rules: &CopyRules, rel: &Path, is_dir: bool) -> bool {
    let rel_norm = normalize_rel_path(rel);

    if let Some(exclude_set) = &rules.exclude_set {
        if exclude_set.is_match(&rel_norm) {
            return false;
        }
    }

    if let Some(include_set) = &rules.include_set {
        return matches_or_has_descendant_match(
            include_set,
            &rules.include_patterns,
            &rel_norm,
            is_dir,
        );
    }

    true
}

fn copy_non_repo_root_entries(
    root: &Path,
    workspace_root: &Path,
    manifest: &ManifestFile,
    rules: &CopyRules,
) -> Result<()> {
    let managed_repos: BTreeSet<String> = manifest
        .repos
        .iter()
        .map(|repo| repo.name.clone())
        .collect();

    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".etz"
            || name == ".etzcopy"
            || name == ".etzignore"
            || managed_repos.contains(&name)
        {
            continue;
        }

        let source = entry.path();
        let target = workspace_root.join(&name);
        copy_path_recursive(root, &source, &target, rules)?;
    }

    Ok(())
}

fn copy_path_recursive(root: &Path, source: &Path, target: &Path, rules: &CopyRules) -> Result<()> {
    if target.exists() {
        bail!("target path already exists at {}", target.display());
    }

    let rel = source.strip_prefix(root).unwrap_or(source);
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to read metadata for {}", source.display()))?;
    let file_type = metadata.file_type();
    let is_dir = file_type.is_dir();

    if !should_copy_relative(rules, rel, is_dir) {
        return Ok(());
    }

    if file_type.is_symlink() {
        copy_symlink(source, target)?;
        return Ok(());
    }

    if file_type.is_file() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(source, target).with_context(|| {
            format!(
                "failed to copy file from {} to {}",
                source.display(),
                target.display()
            )
        })?;
        return Ok(());
    }

    if is_dir {
        fs::create_dir_all(target)
            .with_context(|| format!("failed to create {}", target.display()))?;
        for entry in
            fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
        {
            let entry = entry?;
            let child_source = entry.path();
            let child_target = target.join(entry.file_name());
            copy_path_recursive(root, &child_source, &child_target, rules)?;
        }
        return Ok(());
    }

    bail!("unsupported file type at {}", source.display());
}

#[cfg(unix)]
fn copy_symlink(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs as unix_fs;

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let link_target = fs::read_link(source)
        .with_context(|| format!("failed to read link {}", source.display()))?;
    unix_fs::symlink(&link_target, target).with_context(|| {
        format!(
            "failed to create symlink {} -> {}",
            target.display(),
            link_target.display()
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, _target: &Path) -> Result<()> {
    bail!(
        "copying symlinks is only supported on unix platforms (source: {})",
        source.display()
    )
}

pub fn list_workspaces(root: &Path) -> Result<()> {
    let loaded = load(root)?;

    if loaded.state.workspaces.is_empty() {
        println!("No workspaces found");
        return Ok(());
    }

    for (name, workspace) in &loaded.state.workspaces {
        println!(
            "{}\tbranch={}\trepos={}",
            name,
            workspace.branch,
            workspace.repos.len()
        );
    }

    Ok(())
}

pub fn status_workspaces(
    root: &Path,
    workspace: Option<&str>,
    changed_only: bool,
    summary_only: bool,
    json: bool,
) -> Result<()> {
    let loaded = load(root)?;
    let statuses = collect_statuses(&loaded, workspace)?;

    let workspaces_total = statuses.len() as u32;
    let repos_total = statuses.iter().map(|ws| ws.repos.len() as u32).sum::<u32>();
    let dirty_repos_total = statuses
        .iter()
        .flat_map(|ws| ws.repos.iter())
        .filter(|repo| repo.dirty.unwrap_or(false))
        .count() as u32;

    let mut shown = Vec::<WorkspaceStatus>::new();
    for mut ws in statuses {
        if changed_only {
            ws.repos.retain(is_repo_changed);
        }
        if !changed_only || !ws.repos.is_empty() {
            shown.push(ws);
        }
    }

    let summary = StatusSummary {
        workspaces_total,
        workspaces_shown: shown.len() as u32,
        repos_total,
        repos_shown: shown.iter().map(|ws| ws.repos.len() as u32).sum(),
        dirty_repos_total,
        dirty_repos_shown: shown
            .iter()
            .flat_map(|ws| ws.repos.iter())
            .filter(|repo| repo.dirty.unwrap_or(false))
            .count() as u32,
    };

    let response = StatusResponse {
        changed_only,
        summary: summary.clone(),
        workspaces: shown.clone(),
    };

    if json {
        return print_json("status", response);
    }

    if response.workspaces.is_empty() {
        println!("No workspaces found");
        return Ok(());
    }

    if summary_only {
        println!(
            "workspaces={}/{} repos={}/{} dirty={}/{} changed_only={}",
            summary.workspaces_shown,
            summary.workspaces_total,
            summary.repos_shown,
            summary.repos_total,
            summary.dirty_repos_shown,
            summary.dirty_repos_total,
            changed_only
        );
        for ws in &response.workspaces {
            let dirty_count = ws
                .repos
                .iter()
                .filter(|repo| repo.dirty.unwrap_or(false))
                .count();
            println!(
                "  {} branch={} repos={} dirty={}",
                ws.workspace,
                ws.branch,
                ws.repos.len(),
                dirty_count
            );
        }
        return Ok(());
    }

    for ws in response.workspaces {
        println!("workspace: {} (branch={})", ws.workspace, ws.branch);
        for repo in ws.repos {
            let mut extra = String::new();
            if let (Some(ahead), Some(behind)) = (repo.ahead, repo.behind) {
                extra = format!(" ahead={} behind={}", ahead, behind);
            }

            println!(
                "  {}\texists={}\tbranch={}\tdirty={}\tstaged={}\tunstaged={}\tuntracked={}\tconflicts={}{}",
                repo.repo,
                repo.exists,
                repo.branch
                    .unwrap_or_else(|| "<detached-or-missing>".to_string()),
                repo.dirty
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                repo.staged_files
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                repo.unstaged_files
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                repo.untracked_files
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                repo.conflicts
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                extra
            );
        }
    }

    println!(
        "summary: workspaces={}/{} repos={}/{} dirty={}/{}",
        summary.workspaces_shown,
        summary.workspaces_total,
        summary.repos_shown,
        summary.repos_total,
        summary.dirty_repos_shown,
        summary.dirty_repos_total
    );

    Ok(())
}

fn is_repo_changed(repo: &RepoStatus) -> bool {
    if !repo.exists {
        return true;
    }

    if repo.dirty.unwrap_or(false) || repo.conflicts.unwrap_or(false) {
        return true;
    }

    if let Some(ahead) = repo.ahead
        && ahead > 0
    {
        return true;
    }
    if let Some(behind) = repo.behind
        && behind > 0
    {
        return true;
    }

    false
}

fn collect_statuses(loaded: &Loaded, workspace: Option<&str>) -> Result<Vec<WorkspaceStatus>> {
    let mut output = Vec::new();

    let selected: Vec<(String, &WorkspaceState)> = if let Some(name) = workspace {
        vec![(
            name.to_string(),
            resolve_existing_workspace(&loaded.state, name)?,
        )]
    } else {
        loaded
            .state
            .workspaces
            .iter()
            .map(|(name, ws)| (name.clone(), ws))
            .collect()
    };

    for (workspace_name, ws) in selected {
        let mut repos = Vec::new();
        for (repo_name, repo_state) in &ws.repos {
            let source_path = repo_state.source_path.clone();
            let worktree_path = repo_state.worktree_path.clone();
            let worktree_path_buf = PathBuf::from(&worktree_path);

            let exists = worktree_path_buf.exists() && git::is_git_repo(&worktree_path_buf);
            let mut branch = None;
            let mut dirty = None;
            let mut staged_files = None;
            let mut unstaged_files = None;
            let mut untracked_files = None;
            let mut conflicts = None;
            let mut ahead = None;
            let mut behind = None;

            if exists {
                branch = git::current_branch(&worktree_path_buf)?;
                let counts = git::status_counts(&worktree_path_buf)?;
                staged_files = Some(counts.staged);
                unstaged_files = Some(counts.unstaged);
                untracked_files = Some(counts.untracked);
                dirty = Some(counts.staged + counts.unstaged + counts.untracked > 0);
                conflicts = Some(git::has_conflicts(&worktree_path_buf)?);
                if let Some((a, b)) = git::ahead_behind(&worktree_path_buf)? {
                    ahead = Some(a);
                    behind = Some(b);
                }
            }

            repos.push(RepoStatus {
                repo: repo_name.clone(),
                source_path,
                worktree_path,
                exists,
                branch,
                dirty,
                staged_files,
                unstaged_files,
                untracked_files,
                conflicts,
                ahead,
                behind,
            });
        }

        output.push(WorkspaceStatus {
            workspace: workspace_name,
            branch: ws.branch.clone(),
            repos,
        });
    }

    Ok(output)
}

pub fn commit_workspace(
    root: &Path,
    workspace: &str,
    message: Option<&str>,
    stage_all: bool,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let commit_message = message.map(str::trim);
    if !dry_run {
        let commit_message = commit_message.ok_or_else(|| anyhow!("commit message is required"))?;
        if commit_message.is_empty() {
            bail!("commit message cannot be empty");
        }
    }

    let loaded = load(root)?;
    let workspace_state = resolve_existing_workspace(&loaded.state, workspace)?;

    let mut ordered_repos: Vec<(&String, &WorkspaceRepoState)> =
        workspace_state.repos.iter().collect();
    ordered_repos.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (repo_name, repo_state) in &ordered_repos {
        let repo_path = PathBuf::from(&repo_state.worktree_path);
        if !repo_path.exists() || !git::is_git_repo(&repo_path) {
            bail!(
                "workspace '{}' repo '{}' is missing at {}",
                workspace,
                repo_name,
                repo_path.display()
            );
        }

        let current = git::current_branch(&repo_path)?;
        let current = current.ok_or_else(|| {
            anyhow!(
                "workspace '{}' repo '{}' is in detached HEAD",
                workspace,
                repo_name
            )
        })?;

        if current != workspace_state.branch {
            bail!(
                "workspace '{}' repo '{}' is on '{}' (expected '{}')",
                workspace,
                repo_name,
                current,
                workspace_state.branch
            );
        }

        if git::has_conflicts(&repo_path)? {
            bail!(
                "workspace '{}' repo '{}' has unresolved merge conflicts",
                workspace,
                repo_name
            );
        }
    }

    let mut auto_staged_repos = Vec::new();
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    let mut skipped = Vec::new();

    if stage_all {
        if !dry_run {
            for (_, repo_state) in &ordered_repos {
                let repo_path = PathBuf::from(&repo_state.worktree_path);
                git::git_ok(&repo_path, ["add", "-A"])?;
            }
        }

        for (repo_name, repo_state) in &ordered_repos {
            let repo_path = PathBuf::from(&repo_state.worktree_path);
            let counts = git::status_counts(&repo_path)?;

            let has_changes = counts.staged + counts.unstaged + counts.untracked > 0;
            let has_staged_after_add = if dry_run {
                has_changes
            } else {
                git::has_staged_changes(&repo_path)?
            };

            if has_staged_after_add {
                candidates.push(((*repo_name).clone(), repo_path.clone()));
            } else {
                skipped.push((*repo_name).clone());
            }
        }
    } else {
        for (repo_name, repo_state) in &ordered_repos {
            let repo_path = PathBuf::from(&repo_state.worktree_path);
            if git::has_staged_changes(&repo_path)? {
                candidates.push(((*repo_name).clone(), repo_path));
            } else {
                skipped.push((*repo_name).clone());
            }
        }

        if candidates.is_empty() {
            let mut auto_stage_targets: Vec<(String, PathBuf)> = Vec::new();
            for (repo_name, repo_state) in &ordered_repos {
                let repo_path = PathBuf::from(&repo_state.worktree_path);
                if git::has_unstaged_tracked_changes(&repo_path)? {
                    auto_stage_targets.push(((*repo_name).clone(), repo_path));
                }
            }

            if !auto_stage_targets.is_empty() {
                if !dry_run {
                    for (_, repo_path) in &auto_stage_targets {
                        git::git_ok(repo_path, ["add", "-u"])?;
                    }
                }
                auto_staged_repos = auto_stage_targets
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect();

                candidates = auto_stage_targets;
                skipped = ordered_repos
                    .iter()
                    .map(|(repo_name, _)| (*repo_name).clone())
                    .filter(|name| !auto_staged_repos.contains(name))
                    .collect();
            }
        }
    }

    if dry_run {
        let summary = CommitSummary {
            workspace: workspace.to_string(),
            branch: workspace_state.branch.clone(),
            dry_run: true,
            planned_commits: candidates.iter().map(|(name, _)| name.clone()).collect(),
            auto_staged: auto_staged_repos,
            committed: Vec::new(),
            skipped,
            rolled_back: Vec::new(),
            rollback_failed: Vec::new(),
        };

        if json {
            print_json("commit", summary)?;
        } else {
            println!(
                "Dry run for workspace '{}': would_commit={} would_skip={}",
                summary.workspace,
                summary.planned_commits.len(),
                summary.skipped.len()
            );
            if !summary.auto_staged.is_empty() {
                println!(
                    "Would auto-stage tracked changes in repos: {}",
                    summary.auto_staged.join(", ")
                );
            }
            if !summary.planned_commits.is_empty() {
                println!("Would commit repos: {}", summary.planned_commits.join(", "));
            }
            if !summary.skipped.is_empty() {
                println!("Would skip repos: {}", summary.skipped.join(", "));
            }
        }

        return Ok(());
    }

    let mut committed: Vec<(String, PathBuf)> = Vec::new();
    let commit_message = commit_message.unwrap_or_default();

    for (repo_name, repo_path) in &candidates {
        let out = git::git(repo_path, ["commit", "-m", commit_message])?;
        if out.success {
            committed.push((repo_name.clone(), repo_path.clone()));
            continue;
        }

        let (rolled_back, rollback_failed) = rollback_commits(&committed);
        let detail = if out.stderr.is_empty() {
            "unknown git error".to_string()
        } else {
            out.stderr
        };

        let summary = CommitSummary {
            workspace: workspace.to_string(),
            branch: workspace_state.branch.clone(),
            dry_run: false,
            planned_commits: Vec::new(),
            auto_staged: auto_staged_repos,
            committed: committed.iter().map(|(name, _)| name.clone()).collect(),
            skipped,
            rolled_back,
            rollback_failed,
        };

        if json {
            print_json("commit", summary)?;
        }

        return errors::err(
            EXIT_GIT,
            format!(
                "commit failed for repo '{}' in workspace '{}': {}",
                repo_name, workspace, detail
            ),
        );
    }

    let summary = CommitSummary {
        workspace: workspace.to_string(),
        branch: workspace_state.branch.clone(),
        dry_run: false,
        planned_commits: Vec::new(),
        auto_staged: auto_staged_repos,
        committed: committed.into_iter().map(|(name, _)| name).collect(),
        skipped,
        rolled_back: Vec::new(),
        rollback_failed: Vec::new(),
    };

    if json {
        print_json("commit", summary)?;
    } else {
        println!(
            "Workspace '{}' commit complete: committed={} skipped={}",
            summary.workspace,
            summary.committed.len(),
            summary.skipped.len()
        );
        if !summary.auto_staged.is_empty() {
            println!(
                "Auto-staged tracked changes in repos: {}",
                summary.auto_staged.join(", ")
            );
        }
        if !summary.committed.is_empty() {
            println!("Committed repos: {}", summary.committed.join(", "));
        }
        if !summary.skipped.is_empty() {
            println!("Skipped repos: {}", summary.skipped.join(", "));
        }
    }

    Ok(())
}

fn rollback_commits(committed: &[(String, PathBuf)]) -> (Vec<String>, Vec<String>) {
    let mut rolled_back = Vec::new();
    let mut failed = Vec::new();

    for (repo_name, repo_path) in committed.iter().rev() {
        match git::git(repo_path, ["reset", "--soft", "HEAD~1"]) {
            Ok(out) if out.success => rolled_back.push(repo_name.clone()),
            Ok(out) => {
                failed.push(format!("{}: {}", repo_name, out.stderr));
            }
            Err(err) => {
                failed.push(format!("{}: {}", repo_name, err));
            }
        }
    }

    (rolled_back, failed)
}

pub fn push_workspace(root: &Path, workspace: &str, dry_run: bool, json: bool) -> Result<()> {
    let loaded = load(root)?;
    let workspace_state = resolve_existing_workspace(&loaded.state, workspace)?;

    let mut ordered_repos: Vec<(&String, &WorkspaceRepoState)> =
        workspace_state.repos.iter().collect();
    ordered_repos.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (repo_name, repo_state) in &ordered_repos {
        let repo_path = PathBuf::from(&repo_state.worktree_path);
        if !repo_path.exists() || !git::is_git_repo(&repo_path) {
            return errors::err(
                EXIT_GIT,
                format!(
                    "workspace '{}' repo '{}' is missing at {}",
                    workspace,
                    repo_name,
                    repo_path.display()
                ),
            );
        }

        let current = git::current_branch(&repo_path)?;
        let current = current.ok_or_else(|| {
            errors::exit_error(
                EXIT_GIT,
                format!(
                    "workspace '{}' repo '{}' is in detached HEAD",
                    workspace, repo_name
                ),
            )
        })?;

        if current != workspace_state.branch {
            return errors::err(
                EXIT_GIT,
                format!(
                    "workspace '{}' repo '{}' is on '{}' (expected '{}')",
                    workspace, repo_name, current, workspace_state.branch
                ),
            );
        }
    }

    let mut repos = Vec::<PushRepoResult>::new();
    let mut pushed = Vec::<String>::new();
    let mut skipped = Vec::<String>::new();
    let mut failed = Vec::<String>::new();

    for (repo_name, repo_state) in ordered_repos {
        let repo_path = PathBuf::from(&repo_state.worktree_path);
        let ahead_behind = git::ahead_behind(&repo_path)?;
        let (ahead, behind) = ahead_behind.unwrap_or((0, 0));

        if ahead == 0 {
            skipped.push(repo_name.clone());
            repos.push(PushRepoResult {
                repo: repo_name.clone(),
                ahead: Some(ahead),
                behind: Some(behind),
                pushed: false,
                skipped_reason: Some("up-to-date".to_string()),
                error: None,
            });
            continue;
        }

        if dry_run {
            pushed.push(repo_name.clone());
            repos.push(PushRepoResult {
                repo: repo_name.clone(),
                ahead: Some(ahead),
                behind: Some(behind),
                pushed: false,
                skipped_reason: Some("dry-run".to_string()),
                error: None,
            });
            continue;
        }

        let out = git::git(
            &repo_path,
            [
                "push",
                "--set-upstream",
                "origin",
                workspace_state.branch.as_str(),
            ],
        )?;
        if out.success {
            pushed.push(repo_name.clone());
            repos.push(PushRepoResult {
                repo: repo_name.clone(),
                ahead: Some(ahead),
                behind: Some(behind),
                pushed: true,
                skipped_reason: None,
                error: None,
            });
        } else {
            failed.push(repo_name.clone());
            let detail = if out.stderr.trim().is_empty() {
                "unknown git error".to_string()
            } else {
                out.stderr.trim().to_string()
            };
            repos.push(PushRepoResult {
                repo: repo_name.clone(),
                ahead: Some(ahead),
                behind: Some(behind),
                pushed: false,
                skipped_reason: None,
                error: Some(detail),
            });
        }
    }

    let summary = PushSummary {
        workspace: workspace.to_string(),
        branch: workspace_state.branch.clone(),
        dry_run,
        pushed,
        skipped,
        failed: failed.clone(),
        repos,
    };

    if json {
        print_json("push", summary)?;
    } else {
        if dry_run {
            println!(
                "Workspace '{}' dry-run push: would_push={} skipped={}",
                workspace,
                summary.pushed.len(),
                summary.skipped.len()
            );
        } else {
            println!(
                "Workspace '{}' push complete: pushed={} skipped={} failed={}",
                workspace,
                summary.pushed.len(),
                summary.skipped.len(),
                summary.failed.len()
            );
        }

        if !summary.pushed.is_empty() {
            if dry_run {
                println!("Would push repos: {}", summary.pushed.join(", "));
            } else {
                println!("Pushed repos: {}", summary.pushed.join(", "));
            }
        }
        if !summary.skipped.is_empty() {
            println!("Skipped repos: {}", summary.skipped.join(", "));
        }
        if !summary.failed.is_empty() {
            println!("Failed repos: {}", summary.failed.join(", "));
        }
    }

    if !failed.is_empty() {
        return errors::err(
            EXIT_GIT,
            format!(
                "push failed for {} repo(s) in workspace '{}'",
                failed.len(),
                workspace
            ),
        );
    }

    Ok(())
}

pub fn remove_workspace(root: &Path, workspace: &str, force: bool) -> Result<()> {
    assert_workspace_name_valid(workspace)?;
    let mut loaded = load(root)?;

    let workspace_state = resolve_existing_workspace(&loaded.state, workspace)?.clone();

    let mut removed: Vec<(String, PathBuf, PathBuf)> = Vec::new();

    let mut ordered: Vec<(&String, &WorkspaceRepoState)> = workspace_state.repos.iter().collect();
    ordered.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (repo_name, repo_state) in ordered {
        let source = PathBuf::from(&repo_state.source_path);
        let worktree = PathBuf::from(&repo_state.worktree_path);

        if !worktree.exists() {
            if force {
                continue;
            }

            let (restored, restore_failures) =
                rollback_removed_worktrees(&removed, &workspace_state.branch);
            let mut msg = format!(
                "worktree missing for repo '{}' at {}",
                repo_name,
                worktree.display()
            );
            if !restore_failures.is_empty() {
                msg.push_str(&format!(
                    " (rollback restored {} and failed {}: {})",
                    restored.len(),
                    restore_failures.len(),
                    restore_failures.join("; ")
                ));
            }
            bail!(msg);
        }

        let mut args = vec!["worktree".to_string(), "remove".to_string()];
        if force {
            args.push("--force".to_string());
        }
        args.push(worktree.to_string_lossy().to_string());

        let out = match git::git(&source, args.iter().map(String::as_str)) {
            Ok(out) => out,
            Err(err) => {
                let (restored, restore_failures) =
                    rollback_removed_worktrees(&removed, &workspace_state.branch);
                if restore_failures.is_empty() {
                    bail!(
                        "failed to invoke git worktree remove for repo '{}': {} (rollback restored {})",
                        repo_name,
                        err,
                        restored.len()
                    );
                }
                bail!(
                    "failed to invoke git worktree remove for repo '{}': {} (rollback restored {} and failed {}: {})",
                    repo_name,
                    err,
                    restored.len(),
                    restore_failures.len(),
                    restore_failures.join("; ")
                );
            }
        };
        if out.success {
            removed.push((repo_name.clone(), source, worktree));
            continue;
        }

        let (restored, restore_failures) =
            rollback_removed_worktrees(&removed, &workspace_state.branch);
        let detail = if out.stderr.is_empty() {
            "unknown git error".to_string()
        } else {
            out.stderr
        };
        if restore_failures.is_empty() {
            bail!(
                "failed to remove worktree for repo '{}': {} (rollback restored {})",
                repo_name,
                detail,
                restored.len()
            );
        }

        bail!(
            "failed to remove worktree for repo '{}': {} (rollback restored {} and failed {}: {})",
            repo_name,
            detail,
            restored.len(),
            restore_failures.len(),
            restore_failures.join("; ")
        );
    }

    loaded.state.workspaces.remove(workspace);
    save_state(&loaded.paths, &loaded.state)?;

    let workspace_dir = loaded.paths.workspace_dir(&loaded.config, workspace);
    if workspace_dir.exists() {
        fs::remove_dir_all(&workspace_dir)
            .with_context(|| format!("failed to remove {}", workspace_dir.display()))?;
    }

    println!("Removed workspace '{}'", workspace);
    Ok(())
}

fn rollback_removed_worktrees(
    removed: &[(String, PathBuf, PathBuf)],
    branch: &str,
) -> (Vec<String>, Vec<String>) {
    let mut restored = Vec::new();
    let mut restore_failures = Vec::new();

    for (repo_name, source_path, worktree_path) in removed.iter().rev() {
        if let Some(parent) = worktree_path.parent() {
            fs::create_dir_all(parent).ok();
        }

        match git::git(
            source_path,
            [
                "worktree",
                "add",
                worktree_path.to_string_lossy().as_ref(),
                branch,
            ],
        ) {
            Ok(out) if out.success => restored.push(repo_name.clone()),
            Ok(out) => {
                restore_failures.push(format!("{}: {}", repo_name, out.stderr));
            }
            Err(err) => {
                restore_failures.push(format!("{}: {}", repo_name, err));
            }
        }
    }

    (restored, restore_failures)
}

pub fn prune_worktrees(root: &Path) -> Result<()> {
    let mut loaded = load(root)?;

    for repo in &loaded.manifest.repos {
        let source = loaded.paths.root.join(&repo.path);
        if git::is_git_repo(&source) {
            let _ = git::git(&source, ["worktree", "prune"])?;
        }
    }

    let mut dropped_repos = 0usize;
    let mut dropped_workspaces = 0usize;

    loaded.state.workspaces.retain(|_, ws| {
        let before = ws.repos.len();
        ws.repos
            .retain(|_, repo| PathBuf::from(&repo.worktree_path).exists());
        let after = ws.repos.len();
        dropped_repos += before.saturating_sub(after);
        let keep = !ws.repos.is_empty();
        if !keep {
            dropped_workspaces += 1;
        }
        keep
    });

    save_state(&loaded.paths, &loaded.state)?;

    println!(
        "Prune complete: removed {} stale repo entries across {} workspace(s)",
        dropped_repos, dropped_workspaces
    );

    Ok(())
}

pub fn doctor(root: &Path, fix: bool, json: bool) -> Result<()> {
    let mut loaded = load(root)?;
    let mut issues = Vec::<DoctorIssue>::new();
    let mut fixes_applied = Vec::<String>::new();
    let mut state_changed = false;

    let manifest_names: BTreeSet<String> = loaded
        .manifest
        .repos
        .iter()
        .map(|repo| repo.name.clone())
        .collect();

    for repo in &loaded.manifest.repos {
        let source = loaded.paths.root.join(&repo.path);
        if !source.exists() {
            issues.push(DoctorIssue {
                severity: "error".to_string(),
                code: "missing_source_repo".to_string(),
                message: format!("source repo '{}' is missing", repo.name),
                workspace: None,
                repo: Some(repo.name.clone()),
                path: Some(source.to_string_lossy().to_string()),
                fix: Some("restore repo folder or run `etz refresh`".to_string()),
            });
            continue;
        }

        if !git::is_git_repo(&source) {
            issues.push(DoctorIssue {
                severity: "error".to_string(),
                code: "invalid_source_repo".to_string(),
                message: format!("source path for '{}' is not a git repo", repo.name),
                workspace: None,
                repo: Some(repo.name.clone()),
                path: Some(source.to_string_lossy().to_string()),
                fix: Some("repair repository metadata or remove it from manifest".to_string()),
            });
        }
    }

    let workspace_names: Vec<String> = loaded.state.workspaces.keys().cloned().collect();
    for workspace_name in workspace_names {
        let Some(workspace_snapshot) = loaded.state.workspaces.get(&workspace_name).cloned() else {
            continue;
        };

        for manifest_repo in &loaded.manifest.repos {
            if !workspace_snapshot.repos.contains_key(&manifest_repo.name) {
                issues.push(DoctorIssue {
                    severity: "warn".to_string(),
                    code: "workspace_incomplete".to_string(),
                    message: format!(
                        "workspace '{}' does not contain repo '{}'",
                        workspace_name, manifest_repo.name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(manifest_repo.name.clone()),
                    path: None,
                    fix: Some(format!(
                        "remove and recreate workspace '{}' to rehydrate missing repo",
                        workspace_name
                    )),
                });
            }
        }

        let mut repos_to_remove = Vec::<String>::new();
        for (repo_name, repo_state) in &workspace_snapshot.repos {
            let worktree_path = PathBuf::from(&repo_state.worktree_path);
            let source_path = PathBuf::from(&repo_state.source_path);

            if !manifest_names.contains(repo_name) {
                issues.push(DoctorIssue {
                    severity: "warn".to_string(),
                    code: "stale_workspace_repo".to_string(),
                    message: format!(
                        "workspace '{}' tracks repo '{}' not present in manifest",
                        workspace_name, repo_name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(worktree_path.to_string_lossy().to_string()),
                    fix: Some("remove stale state entry or refresh workspace".to_string()),
                });
                if fix {
                    repos_to_remove.push(repo_name.clone());
                    fixes_applied.push(format!(
                        "removed stale state entry '{}' from workspace '{}'",
                        repo_name, workspace_name
                    ));
                }
            }

            if !source_path.exists() || !git::is_git_repo(&source_path) {
                issues.push(DoctorIssue {
                    severity: "error".to_string(),
                    code: "workspace_source_missing".to_string(),
                    message: format!(
                        "workspace '{}' repo '{}' source is missing or invalid",
                        workspace_name, repo_name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(source_path.to_string_lossy().to_string()),
                    fix: Some("restore source repo or remove workspace".to_string()),
                });
            }

            if !worktree_path.exists() {
                issues.push(DoctorIssue {
                    severity: "error".to_string(),
                    code: "missing_worktree".to_string(),
                    message: format!(
                        "workspace '{}' repo '{}' worktree is missing",
                        workspace_name, repo_name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(worktree_path.to_string_lossy().to_string()),
                    fix: Some("remove stale state entry or recreate workspace".to_string()),
                });
                if fix {
                    repos_to_remove.push(repo_name.clone());
                    fixes_applied.push(format!(
                        "removed missing worktree state for '{}' in workspace '{}'",
                        repo_name, workspace_name
                    ));
                }
                continue;
            }

            if !git::is_git_repo(&worktree_path) {
                issues.push(DoctorIssue {
                    severity: "error".to_string(),
                    code: "invalid_worktree".to_string(),
                    message: format!(
                        "workspace '{}' repo '{}' path is not a valid git worktree",
                        workspace_name, repo_name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(worktree_path.to_string_lossy().to_string()),
                    fix: Some("remove stale state entry or recreate workspace".to_string()),
                });
                if fix {
                    repos_to_remove.push(repo_name.clone());
                    fixes_applied.push(format!(
                        "removed invalid worktree state for '{}' in workspace '{}'",
                        repo_name, workspace_name
                    ));
                }
                continue;
            }

            let current_branch = git::current_branch(&worktree_path)?;
            if current_branch.is_none() {
                issues.push(DoctorIssue {
                    severity: "error".to_string(),
                    code: "detached_head".to_string(),
                    message: format!(
                        "workspace '{}' repo '{}' is detached",
                        workspace_name, repo_name
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(worktree_path.to_string_lossy().to_string()),
                    fix: Some(format!("checkout branch '{}'", workspace_snapshot.branch)),
                });

                if fix {
                    let out = git::git(
                        &worktree_path,
                        ["checkout", workspace_snapshot.branch.as_str()],
                    )?;
                    if out.success {
                        fixes_applied.push(format!(
                            "checked out '{}' in workspace '{}' repo '{}'",
                            workspace_snapshot.branch, workspace_name, repo_name
                        ));
                    } else {
                        let detail = if out.stderr.trim().is_empty() {
                            "unknown git error".to_string()
                        } else {
                            out.stderr.trim().to_string()
                        };
                        issues.push(DoctorIssue {
                            severity: "error".to_string(),
                            code: "fix_checkout_failed".to_string(),
                            message: format!(
                                "failed to checkout '{}' for workspace '{}' repo '{}': {}",
                                workspace_snapshot.branch, workspace_name, repo_name, detail
                            ),
                            workspace: Some(workspace_name.clone()),
                            repo: Some(repo_name.clone()),
                            path: Some(worktree_path.to_string_lossy().to_string()),
                            fix: None,
                        });
                    }
                }
                continue;
            }

            let current_branch = current_branch.unwrap_or_default();
            if current_branch != workspace_snapshot.branch {
                issues.push(DoctorIssue {
                    severity: "error".to_string(),
                    code: "branch_drift".to_string(),
                    message: format!(
                        "workspace '{}' repo '{}' is on '{}' (expected '{}')",
                        workspace_name, repo_name, current_branch, workspace_snapshot.branch
                    ),
                    workspace: Some(workspace_name.clone()),
                    repo: Some(repo_name.clone()),
                    path: Some(worktree_path.to_string_lossy().to_string()),
                    fix: Some(format!("checkout '{}'", workspace_snapshot.branch)),
                });

                if fix {
                    let out = git::git(
                        &worktree_path,
                        ["checkout", workspace_snapshot.branch.as_str()],
                    )?;
                    if out.success {
                        fixes_applied.push(format!(
                            "checked out '{}' in workspace '{}' repo '{}'",
                            workspace_snapshot.branch, workspace_name, repo_name
                        ));
                    } else {
                        let detail = if out.stderr.trim().is_empty() {
                            "unknown git error".to_string()
                        } else {
                            out.stderr.trim().to_string()
                        };
                        issues.push(DoctorIssue {
                            severity: "error".to_string(),
                            code: "fix_checkout_failed".to_string(),
                            message: format!(
                                "failed to checkout '{}' for workspace '{}' repo '{}': {}",
                                workspace_snapshot.branch, workspace_name, repo_name, detail
                            ),
                            workspace: Some(workspace_name.clone()),
                            repo: Some(repo_name.clone()),
                            path: Some(worktree_path.to_string_lossy().to_string()),
                            fix: None,
                        });
                    }
                }
            }
        }

        if fix && !repos_to_remove.is_empty() {
            if let Some(ws_mut) = loaded.state.workspaces.get_mut(&workspace_name) {
                let before = ws_mut.repos.len();
                ws_mut
                    .repos
                    .retain(|name, _| !repos_to_remove.contains(name));
                if ws_mut.repos.len() != before {
                    state_changed = true;
                }
            }
        }
    }

    if fix {
        let before = loaded.state.workspaces.len();
        loaded.state.workspaces.retain(|workspace_name, ws| {
            let keep = !ws.repos.is_empty();
            if !keep {
                fixes_applied.push(format!(
                    "removed empty workspace '{}' from state",
                    workspace_name
                ));
            }
            keep
        });
        if loaded.state.workspaces.len() != before {
            state_changed = true;
        }
    }

    if fix && state_changed {
        save_state(&loaded.paths, &loaded.state)?;
    }

    let response = DoctorResponse {
        fix_mode: fix,
        fixes_applied,
        issues,
    };

    if json {
        return print_json("doctor", response);
    }

    if response.issues.is_empty() {
        if response.fix_mode {
            println!("Doctor found no issues (fix mode enabled)");
        } else {
            println!("Doctor found no issues");
        }
    } else {
        for issue in &response.issues {
            println!(
                "[{}] {}: {}",
                issue.severity.to_uppercase(),
                issue.code,
                issue.message
            );
            if let Some(path) = &issue.path {
                println!("  path: {}", path);
            }
            if let Some(fix) = &issue.fix {
                println!("  fix: {}", fix);
            }
        }
        println!("Doctor found {} issue(s)", response.issues.len());
    }

    if response.fix_mode {
        if response.fixes_applied.is_empty() {
            println!("No fixes were applied");
        } else {
            println!("Applied {} fix(es):", response.fixes_applied.len());
            for fix_desc in &response.fixes_applied {
                println!("  - {}", fix_desc);
            }
        }
    }

    Ok(())
}
