pub mod cli;
pub mod discovery;
pub mod errors;
pub mod git;
pub mod model;
pub mod ops;
pub mod storage;

use std::path::Path;

use anyhow::{Result, anyhow};
use cli::{Cli, Commands};
use storage::{find_etz_root, infer_workspace_from_cwd};

pub fn run(cli: Cli, root: &Path) -> Result<()> {
    let resolved_root = find_etz_root(root).unwrap_or_else(|| root.to_path_buf());

    match cli.command {
        Commands::Init => ops::init(root),
        Commands::Add {
            workspace,
            branch,
            no_copy_root,
        } => ops::add_workspace(&resolved_root, &workspace, &branch, !no_copy_root),
        Commands::List => ops::list_workspaces(&resolved_root),
        Commands::Refresh { check, json } => ops::refresh_manifest(&resolved_root, check, json),
        Commands::Status {
            workspace,
            changed,
            summary,
            json,
        } => {
            let inferred_workspace = if workspace.is_none() {
                infer_workspace_from_cwd(&resolved_root, root)?
            } else {
                None
            };
            let selected_workspace = workspace.as_deref().or(inferred_workspace.as_deref());
            ops::status_workspaces(&resolved_root, selected_workspace, changed, summary, json)
        }
        Commands::Commit {
            workspace,
            message,
            all,
            dry_run,
            json,
        } => {
            let workspace = match workspace {
                Some(workspace) => workspace,
                None => infer_workspace_from_cwd(&resolved_root, root)?.ok_or_else(|| {
                    anyhow!(
                        "workspace argument is required unless you run inside .etz/workspaces/<workspace>/..."
                    )
                })?,
            };
            ops::commit_workspace(
                &resolved_root,
                &workspace,
                message.as_deref(),
                all,
                dry_run,
                json,
            )
        }
        Commands::Push {
            workspace,
            dry_run,
            json,
        } => {
            let workspace = match workspace {
                Some(workspace) => workspace,
                None => infer_workspace_from_cwd(&resolved_root, root)?.ok_or_else(|| {
                    anyhow!(
                        "workspace argument is required unless you run inside .etz/workspaces/<workspace>/..."
                    )
                })?,
            };
            ops::push_workspace(&resolved_root, &workspace, dry_run, json)
        }
        Commands::Remove { workspace, force } => {
            ops::remove_workspace(&resolved_root, &workspace, force)
        }
        Commands::Prune => ops::prune_worktrees(&resolved_root),
        Commands::Doctor { fix, json } => ops::doctor(&resolved_root, fix, json),
    }
}
