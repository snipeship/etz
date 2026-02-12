use std::{
    fs,
    path::Component,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    errors::{self, EXIT_NOT_FOUND},
    model::{ConfigFile, ManifestFile, StateFile},
};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root: PathBuf,
    pub etz_dir: PathBuf,
    pub config_path: PathBuf,
    pub manifest_path: PathBuf,
    pub state_path: PathBuf,
}

impl AppPaths {
    pub fn from_root(root: &Path) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to canonicalize root {}", root.display()))?;
        let etz_dir = root.join(".etz");

        Ok(Self {
            root,
            etz_dir: etz_dir.clone(),
            config_path: etz_dir.join("config.toml"),
            manifest_path: etz_dir.join("manifest.lock.toml"),
            state_path: etz_dir.join("state.toml"),
        })
    }

    pub fn ensure_exists(&self) -> Result<()> {
        if !self.etz_dir.exists() {
            return errors::err(
                errors::EXIT_NOT_INITIALIZED,
                format!(
                    "{} is not initialized. Run `etz init` first.",
                    self.root.display()
                ),
            );
        }
        Ok(())
    }

    pub fn workspaces_dir(&self, config: &ConfigFile) -> PathBuf {
        self.etz_dir.join(&config.workspace_dir)
    }

    pub fn workspace_dir(&self, config: &ConfigFile, workspace: &str) -> PathBuf {
        self.workspaces_dir(config).join(workspace)
    }

    pub fn is_initialized(&self) -> bool {
        self.config_path.exists() && self.manifest_path.exists() && self.state_path.exists()
    }

    pub fn initialize(&self) -> Result<()> {
        fs::create_dir_all(&self.etz_dir)
            .with_context(|| format!("failed to create {}", self.etz_dir.display()))
    }
}

pub fn read_toml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value =
        toml::from_str::<T>(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
    Ok(value)
}

pub fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let serialized = toml::to_string_pretty(value)
        .with_context(|| format!("failed to serialize TOML for {}", path.display()))?;
    fs::write(path, serialized).with_context(|| format!("failed to write {}", path.display()))
}

pub fn load_config(paths: &AppPaths) -> Result<ConfigFile> {
    paths.ensure_exists()?;
    if !paths.config_path.exists() {
        bail!(
            "missing config at {}. Run `etz init`.",
            paths.config_path.display()
        );
    }
    read_toml(&paths.config_path)
}

pub fn load_manifest(paths: &AppPaths) -> Result<ManifestFile> {
    paths.ensure_exists()?;
    if !paths.manifest_path.exists() {
        bail!(
            "missing manifest at {}. Run `etz init`.",
            paths.manifest_path.display()
        );
    }
    read_toml(&paths.manifest_path)
}

pub fn load_state(paths: &AppPaths) -> Result<StateFile> {
    paths.ensure_exists()?;
    if !paths.state_path.exists() {
        bail!(
            "missing state at {}. Run `etz init`.",
            paths.state_path.display()
        );
    }
    read_toml(&paths.state_path)
}

pub fn save_config(paths: &AppPaths, config: &ConfigFile) -> Result<()> {
    write_toml(&paths.config_path, config)
}

pub fn save_manifest(paths: &AppPaths, manifest: &ManifestFile) -> Result<()> {
    write_toml(&paths.manifest_path, manifest)
}

pub fn save_state(paths: &AppPaths, state: &StateFile) -> Result<()> {
    write_toml(&paths.state_path, state)
}

pub fn assert_workspace_name_valid(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("workspace name cannot be empty");
    }
    if name.contains('/') || name.contains('\\') {
        bail!("workspace name cannot include path separators");
    }
    if name == "." || name == ".." {
        bail!("workspace name cannot be . or ..");
    }
    if name.starts_with('.') {
        bail!("workspace name cannot start with '.'");
    }
    Ok(())
}

pub fn resolve_existing_workspace<'a>(
    state: &'a StateFile,
    workspace: &str,
) -> Result<&'a crate::model::WorkspaceState> {
    state.workspaces.get(workspace).ok_or_else(|| {
        errors::exit_error(
            EXIT_NOT_FOUND,
            format!("workspace '{}' not found", workspace),
        )
    })
}

pub fn find_etz_root(start: &Path) -> Option<PathBuf> {
    let canonical_start = start.canonicalize().ok()?;

    for ancestor in canonical_start.ancestors() {
        let etz_dir = ancestor.join(".etz");
        if etz_dir.join("config.toml").exists()
            && etz_dir.join("manifest.lock.toml").exists()
            && etz_dir.join("state.toml").exists()
        {
            return Some(ancestor.to_path_buf());
        }
    }

    None
}

pub fn infer_workspace_from_cwd(root: &Path, cwd: &Path) -> Result<Option<String>> {
    let paths = AppPaths::from_root(root)?;
    if !paths.config_path.exists() {
        return Ok(None);
    }

    let config: ConfigFile = read_toml(&paths.config_path)?;
    let workspaces_dir = paths.workspaces_dir(&config);
    if !workspaces_dir.exists() {
        return Ok(None);
    }

    let canonical_cwd = cwd
        .canonicalize()
        .with_context(|| format!("failed to canonicalize cwd {}", cwd.display()))?;
    let canonical_workspaces_dir = workspaces_dir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", workspaces_dir.display()))?;

    let rel = match canonical_cwd.strip_prefix(&canonical_workspaces_dir) {
        Ok(rel) => rel,
        Err(_) => return Ok(None),
    };

    let workspace_name = match rel.components().next() {
        Some(Component::Normal(name)) => name.to_string_lossy().to_string(),
        _ => return Ok(None),
    };

    Ok(Some(workspace_name))
}
