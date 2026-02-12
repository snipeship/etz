use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::{git, model::ManifestRepo};

#[derive(Debug, Clone)]
pub struct DiscoveredRepo {
    pub name: String,
    pub path: PathBuf,
    pub default_branch: String,
}

pub fn discover_repos(root: &Path) -> Result<Vec<DiscoveredRepo>> {
    let mut repos = Vec::new();

    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name == ".etz" {
            continue;
        }

        let file_type = entry.file_type()?;
        if !file_type.is_dir() {
            continue;
        }

        if !git::looks_like_git_repo(&path) {
            continue;
        }

        let default_branch = git::detect_default_branch(&path)?;
        repos.push(DiscoveredRepo {
            name,
            path,
            default_branch,
        });
    }

    repos.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(repos)
}

pub fn to_manifest_entries(root: &Path, discovered: &[DiscoveredRepo]) -> Vec<ManifestRepo> {
    discovered
        .iter()
        .map(|repo| ManifestRepo {
            name: repo.name.clone(),
            path: repo
                .path
                .strip_prefix(root)
                .unwrap_or(&repo.path)
                .to_string_lossy()
                .to_string(),
            default_branch: repo.default_branch.clone(),
        })
        .collect()
}
