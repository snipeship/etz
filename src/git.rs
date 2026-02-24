use std::{ffi::OsStr, path::Path, process::Command};

use anyhow::{Context, Result, bail};

#[derive(Debug)]
pub struct GitOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy)]
pub struct StatusCounts {
    pub staged: u32,
    pub unstaged: u32,
    pub untracked: u32,
}

pub fn git<I, S>(repo: &Path, args: I) -> Result<GitOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .with_context(|| format!("failed to run git in {}", repo.display()))?;

    Ok(GitOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn git_ok<I, S>(repo: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args_vec: Vec<String> = args
        .into_iter()
        .map(|x| x.as_ref().to_string_lossy().to_string())
        .collect();
    let out = git(repo, args_vec.iter().map(String::as_str))?;
    if out.success {
        Ok(out.stdout.trim().to_string())
    } else {
        let joined = args_vec.join(" ");
        let stderr = out.stderr.trim().to_string();
        if stderr.is_empty() {
            bail!("git command failed in {}: git {}", repo.display(), joined,);
        }
        bail!(
            "git command failed in {}: git {}\n{}",
            repo.display(),
            joined,
            stderr,
        );
    }
}

pub fn looks_like_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
}

pub fn is_git_repo(path: &Path) -> bool {
    git(path, ["rev-parse", "--is-inside-work-tree"])
        .map(|o| o.success)
        .unwrap_or(false)
}

/// Detect the repo's default (trunk) branch.
///
/// Priority:
/// 1. `origin/HEAD` symbolic ref — the remote's declared default
/// 2. Local or remote `main` / `master` — conventional trunk names
/// 3. Currently checked-out branch — last resort fallback
/// 4. Hard fallback to `"main"`
pub fn detect_default_branch(repo: &Path) -> Result<String> {
    if let Ok(head) = git_ok(
        repo,
        [
            "symbolic-ref",
            "--quiet",
            "--short",
            "refs/remotes/origin/HEAD",
        ],
    ) {
        let trimmed = head.trim();
        if let Some(branch) = trimmed.strip_prefix("origin/") {
            return Ok(branch.to_string());
        }
    }

    for candidate in ["main", "master"] {
        if branch_exists_local(repo, candidate)? || branch_exists_remote(repo, candidate)? {
            return Ok(candidate.to_string());
        }
    }

    if let Ok(branch) = current_branch(repo) {
        if let Some(branch) = branch {
            return Ok(branch);
        }
    }

    Ok("main".to_string())
}

pub fn branch_exists_local(repo: &Path, branch: &str) -> Result<bool> {
    Ok(git(
        repo,
        [
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )?
    .success)
}

pub fn branch_exists_remote(repo: &Path, branch: &str) -> Result<bool> {
    Ok(git(
        repo,
        [
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/remotes/origin/{branch}"),
        ],
    )?
    .success)
}

pub fn current_branch(repo: &Path) -> Result<Option<String>> {
    let out = git(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    if out.success {
        Ok(Some(out.stdout.trim().to_string()))
    } else {
        Ok(None)
    }
}

pub fn has_conflicts(repo: &Path) -> Result<bool> {
    let out = git_ok(repo, ["diff", "--name-only", "--diff-filter=U"])?;
    Ok(!out.trim().is_empty())
}

pub fn is_dirty(repo: &Path) -> Result<bool> {
    let out = git_ok(repo, ["status", "--porcelain"])?;
    Ok(!out.trim().is_empty())
}

pub fn has_staged_changes(repo: &Path) -> Result<bool> {
    let out = git(repo, ["diff", "--cached", "--quiet"])?;
    if out.success { Ok(false) } else { Ok(true) }
}

pub fn has_unstaged_tracked_changes(repo: &Path) -> Result<bool> {
    let out = git_ok(repo, ["diff", "--name-only"])?;
    Ok(!out.trim().is_empty())
}

pub fn status_counts(repo: &Path) -> Result<StatusCounts> {
    let out = git(repo, ["status", "--porcelain"])?;
    if !out.success {
        bail!("failed to read git status for {}", repo.display());
    }

    let mut counts = StatusCounts {
        staged: 0,
        unstaged: 0,
        untracked: 0,
    };

    for line in out.stdout.lines() {
        if line.len() < 2 {
            continue;
        }

        let bytes = line.as_bytes();
        let x = bytes[0] as char;
        let y = bytes[1] as char;

        if x == '?' && y == '?' {
            counts.untracked += 1;
            continue;
        }

        if x != ' ' {
            counts.staged += 1;
        }
        if y != ' ' {
            counts.unstaged += 1;
        }
    }

    Ok(counts)
}

pub fn ahead_behind(repo: &Path) -> Result<Option<(u32, u32)>> {
    let out = git(
        repo,
        ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
    )?;
    if !out.success {
        return Ok(None);
    }

    let mut parts = out.stdout.split_whitespace();
    let behind = parts.next().and_then(|v| v.parse::<u32>().ok());
    let ahead = parts.next().and_then(|v| v.parse::<u32>().ok());

    match (ahead, behind) {
        (Some(ahead), Some(behind)) => Ok(Some((ahead, behind))),
        _ => Ok(None),
    }
}
