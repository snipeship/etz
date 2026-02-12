use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use etz::{
    git as etz_git,
    model::{ManifestFile, StateFile},
    ops,
    storage::{
        AppPaths, find_etz_root, infer_workspace_from_cwd, load_manifest, load_state, save_manifest,
    },
};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {:?} in {}: {e}", args, path.display()));

    if !output.status.success() {
        panic!(
            "git {:?} failed in {}\nstdout:\n{}\nstderr:\n{}",
            args,
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn try_git(path: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .unwrap_or_else(|e| panic!("failed to run git {:?} in {}: {e}", args, path.display()))
        .status
        .success()
}

fn run_etz(cwd: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_etz"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("failed to run etz {:?} in {}: {e}", args, cwd.display()));

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn init_repo(root: &Path, name: &str) -> PathBuf {
    let repo = root.join(name);
    fs::create_dir_all(&repo).unwrap();

    let init_main_ok = try_git(&repo, &["init", "-b", "main"]);
    if !init_main_ok {
        git(&repo, &["init"]);
        git(&repo, &["checkout", "-b", "main"]);
    }

    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["config", "user.name", "Test User"]);

    fs::write(repo.join("README.md"), format!("# {}\n", name)).unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "init"]);

    repo
}

fn setup_two_repo_root() -> TempDir {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    init_repo(root, "a");
    init_repo(root, "b");

    temp
}

#[test]
fn init_and_add_workspace_creates_worktrees() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-one", "feat-one", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-one/a");
    let b_worktree = root.join(".etz/workspaces/feat-one/b");

    assert!(a_worktree.exists());
    assert!(b_worktree.exists());
    assert_eq!(
        git(&a_worktree, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "feat-one"
    );
    assert_eq!(
        git(&b_worktree, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "feat-one"
    );

    let paths = AppPaths::from_root(root).unwrap();
    let state: StateFile = load_state(&paths).unwrap();
    let ws = state.workspaces.get("feat-one").unwrap();
    assert_eq!(ws.branch, "feat-one");
    assert_eq!(ws.repos.len(), 2);
}

#[test]
fn add_workspace_rolls_back_if_a_repo_fails() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();

    let paths = AppPaths::from_root(root).unwrap();
    let mut manifest: ManifestFile = load_manifest(&paths).unwrap();
    manifest.repos[1].path = "missing-repo".to_string();
    save_manifest(&paths, &manifest).unwrap();

    let err = ops::add_workspace(root, "feat-two", "feat-two", true).unwrap_err();
    assert!(
        err.to_string().contains("source repo") || err.to_string().contains("failed"),
        "unexpected error: {err}"
    );

    assert!(!root.join(".etz/workspaces/feat-two/a").exists());

    let state: StateFile = load_state(&paths).unwrap();
    assert!(!state.workspaces.contains_key("feat-two"));
}

#[test]
fn commit_commits_only_candidate_repos() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-commit", "feat-commit", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-commit/a");
    let b_worktree = root.join(".etz/workspaces/feat-commit/b");

    fs::write(a_worktree.join("README.md"), "updated\n").unwrap();
    git(&a_worktree, &["add", "README.md"]);

    ops::commit_workspace(
        root,
        "feat-commit",
        Some("feat: update a"),
        false,
        false,
        false,
    )
    .unwrap();

    let a_head = git(&a_worktree, &["log", "-1", "--pretty=%s"]);
    let b_head = git(&b_worktree, &["log", "-1", "--pretty=%s"]);

    assert_eq!(a_head, "feat: update a");
    assert_eq!(b_head, "init");
}

#[test]
fn commit_auto_stages_tracked_changes_when_none_are_staged() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-smart", "feat-smart", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-smart/a");
    let b_worktree = root.join(".etz/workspaces/feat-smart/b");

    fs::write(a_worktree.join("README.md"), "auto-stage me\n").unwrap();

    ops::commit_workspace(
        root,
        "feat-smart",
        Some("feat: smart stage"),
        false,
        false,
        false,
    )
    .unwrap();

    let a_head = git(&a_worktree, &["log", "-1", "--pretty=%s"]);
    let b_head = git(&b_worktree, &["log", "-1", "--pretty=%s"]);

    assert_eq!(a_head, "feat: smart stage");
    assert_eq!(b_head, "init");
}

#[test]
fn commit_all_stages_untracked_files() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-all", "feat-all", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-all/a");
    let b_worktree = root.join(".etz/workspaces/feat-all/b");

    fs::write(a_worktree.join("new_file.txt"), "new file\n").unwrap();

    ops::commit_workspace(
        root,
        "feat-all",
        Some("feat: include untracked"),
        true,
        false,
        false,
    )
    .unwrap();

    let a_head = git(&a_worktree, &["log", "-1", "--pretty=%s"]);
    let b_head = git(&b_worktree, &["log", "-1", "--pretty=%s"]);

    assert_eq!(a_head, "feat: include untracked");
    assert_eq!(b_head, "init");
    assert!(
        try_git(
            &a_worktree,
            &["ls-files", "--error-unmatch", "new_file.txt"]
        ),
        "expected new file to be tracked after --all commit"
    );
}

#[test]
fn commit_rolls_back_previous_commits_if_later_repo_fails() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-rb", "feat-rb", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-rb/a");
    let b_worktree = root.join(".etz/workspaces/feat-rb/b");

    fs::write(a_worktree.join("README.md"), "a change\n").unwrap();
    fs::write(b_worktree.join("README.md"), "b change\n").unwrap();
    git(&a_worktree, &["add", "README.md"]);
    git(&b_worktree, &["add", "README.md"]);

    let hook = root.join("b/.git/hooks/pre-commit");
    fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&hook).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook, perms).unwrap();
    }

    let err = ops::commit_workspace(
        root,
        "feat-rb",
        Some("feat: should rollback"),
        false,
        false,
        false,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("commit failed"),
        "unexpected error: {err}"
    );

    let a_head = git(&a_worktree, &["log", "-1", "--pretty=%s"]);
    assert_eq!(a_head, "init");

    let staged = try_git(&a_worktree, &["diff", "--cached", "--quiet"]);
    assert!(
        !staged,
        "expected staged changes to remain after soft reset rollback"
    );
}

#[test]
fn remove_workspace_cleans_state_and_paths() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-remove", "feat-remove", true).unwrap();

    let workspace_root = root.join(".etz/workspaces/feat-remove");
    assert!(workspace_root.exists());

    ops::remove_workspace(root, "feat-remove", false).unwrap();

    assert!(!workspace_root.exists());

    let paths = AppPaths::from_root(root).unwrap();
    let state: StateFile = load_state(&paths).unwrap();
    assert!(!state.workspaces.contains_key("feat-remove"));
}

#[test]
fn add_workspace_copies_root_files_by_default() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    fs::write(root.join("AGENTS.md"), "agent config\n").unwrap();
    fs::create_dir_all(root.join("shared")).unwrap();
    fs::write(root.join("shared/context.txt"), "shared context\n").unwrap();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-copy", "feat-copy", true).unwrap();

    let workspace_root = root.join(".etz/workspaces/feat-copy");
    assert_eq!(
        fs::read_to_string(workspace_root.join("AGENTS.md")).unwrap(),
        "agent config\n"
    );
    assert_eq!(
        fs::read_to_string(workspace_root.join("shared/context.txt")).unwrap(),
        "shared context\n"
    );
}

#[test]
fn add_workspace_can_disable_root_file_copy() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    fs::write(root.join("AGENTS.md"), "agent config\n").unwrap();
    fs::create_dir_all(root.join("shared")).unwrap();
    fs::write(root.join("shared/context.txt"), "shared context\n").unwrap();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-nocopy", "feat-nocopy", false).unwrap();

    let workspace_root = root.join(".etz/workspaces/feat-nocopy");
    assert!(!workspace_root.join("AGENTS.md").exists());
    assert!(!workspace_root.join("shared").exists());
}

#[test]
fn refresh_manifest_detects_added_and_removed_repos() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();

    fs::remove_dir_all(root.join("b")).unwrap();
    init_repo(root, "c");

    ops::refresh_manifest(root, false, false).unwrap();

    let paths = AppPaths::from_root(root).unwrap();
    let manifest: ManifestFile = load_manifest(&paths).unwrap();
    let mut names: Vec<String> = manifest
        .repos
        .iter()
        .map(|repo| repo.name.clone())
        .collect();
    names.sort();

    assert_eq!(names, vec!["a".to_string(), "c".to_string()]);
}

#[test]
fn refresh_check_mode_fails_on_drift() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();

    fs::remove_dir_all(root.join("b")).unwrap();
    init_repo(root, "c");

    let err = ops::refresh_manifest(root, true, false).unwrap_err();
    assert!(err.to_string().contains("manifest drift detected"));
}

#[test]
fn add_workspace_respects_copy_rules() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    fs::write(root.join("AGENTS.md"), "agent config\n").unwrap();
    fs::write(root.join("README.root"), "root readme\n").unwrap();
    fs::create_dir_all(root.join("shared/public")).unwrap();
    fs::create_dir_all(root.join("shared/private")).unwrap();
    fs::write(root.join("shared/public/info.txt"), "public\n").unwrap();
    fs::write(root.join("shared/private/secret.txt"), "secret\n").unwrap();

    fs::write(root.join(".etzcopy"), "AGENTS.md\nshared/**\n").unwrap();
    fs::write(root.join(".etzignore"), "shared/private/**\n").unwrap();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-rules", "feat-rules", true).unwrap();

    let workspace_root = root.join(".etz/workspaces/feat-rules");
    assert!(workspace_root.join("AGENTS.md").exists());
    assert!(workspace_root.join("shared/public/info.txt").exists());
    assert!(!workspace_root.join("shared/private/secret.txt").exists());
    assert!(!workspace_root.join("README.root").exists());
    assert!(!workspace_root.join(".etzcopy").exists());
    assert!(!workspace_root.join(".etzignore").exists());
}

#[test]
fn status_changed_and_summary_flags_work() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-status-flags", "feat-status-flags", true).unwrap();

    let repo_a = root.join(".etz/workspaces/feat-status-flags/a");
    fs::write(repo_a.join("README.md"), "changed\n").unwrap();

    let (ok, stdout, stderr) = run_etz(
        root,
        &["status", "feat-status-flags", "--changed", "--summary"],
    );
    assert!(ok, "status failed: {stderr}");
    assert!(stdout.contains("repos=1/2"), "unexpected output: {stdout}");
    assert!(
        stdout.contains("feat-status-flags"),
        "unexpected output: {stdout}"
    );
}

#[test]
fn doctor_fix_removes_missing_worktree_entries() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-doctor-fix", "feat-doctor-fix", true).unwrap();

    let missing = root.join(".etz/workspaces/feat-doctor-fix/a");
    fs::remove_dir_all(&missing).unwrap();

    ops::doctor(root, true, false).unwrap();

    let paths = AppPaths::from_root(root).unwrap();
    let state: StateFile = load_state(&paths).unwrap();
    let ws = state.workspaces.get("feat-doctor-fix").unwrap();
    assert!(!ws.repos.contains_key("a"));
    assert!(ws.repos.contains_key("b"));
}

#[test]
fn commit_dry_run_does_not_mutate_repos() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-dry", "feat-dry", true).unwrap();

    let a_worktree = root.join(".etz/workspaces/feat-dry/a");
    fs::write(a_worktree.join("README.md"), "dry-run update\n").unwrap();

    ops::commit_workspace(root, "feat-dry", None, false, true, false).unwrap();

    let a_head = git(&a_worktree, &["log", "-1", "--pretty=%s"]);
    assert_eq!(a_head, "init");

    let counts = etz_git::status_counts(&a_worktree).unwrap();
    assert_eq!(counts.staged, 0);
    assert_eq!(counts.unstaged, 1);
}

#[test]
fn infer_workspace_from_nested_workspace_path() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-infer", "feat-infer", true).unwrap();

    let nested_path = root.join(".etz/workspaces/feat-infer/a/src");
    fs::create_dir_all(&nested_path).unwrap();

    let inferred = infer_workspace_from_cwd(root, &nested_path).unwrap();
    assert_eq!(inferred.as_deref(), Some("feat-infer"));
}

#[test]
fn find_etz_root_from_workspace_subpath() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-root", "feat-root", true).unwrap();

    let nested_path = root.join(".etz/workspaces/feat-root/a");
    let found = find_etz_root(&nested_path).unwrap();
    assert_eq!(found, root.canonicalize().unwrap());
}

#[test]
fn status_command_infers_workspace_when_called_inside_workspace() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-status", "feat-status", true).unwrap();

    let inside_workspace = root.join(".etz/workspaces/feat-status/a");
    let (ok, stdout, stderr) = run_etz(&inside_workspace, &["status"]);

    assert!(ok, "status failed: {stderr}");
    assert!(stdout.contains("workspace: feat-status"));
    let workspace_lines = stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("workspace: "))
        .count();
    assert_eq!(workspace_lines, 1);
}

#[test]
fn commit_command_infers_workspace_when_called_inside_workspace() {
    let temp = setup_two_repo_root();
    let root = temp.path();

    ops::init(root).unwrap();
    ops::add_workspace(root, "feat-commit-infer", "feat-commit-infer", true).unwrap();

    let repo_a = root.join(".etz/workspaces/feat-commit-infer/a");
    fs::write(repo_a.join("README.md"), "commit infer\n").unwrap();

    let (ok, _stdout, stderr) = run_etz(&repo_a, &["commit", "-m", "feat: infer workspace"]);
    assert!(ok, "commit failed: {stderr}");

    let head = git(&repo_a, &["log", "-1", "--pretty=%s"]);
    assert_eq!(head, "feat: infer workspace");
}
