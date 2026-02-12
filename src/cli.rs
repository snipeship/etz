use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "etz", about = "Multi-repo worktree manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize .etz metadata in the current directory
    Init,
    /// Add a coordinated workspace backed by git worktrees
    Add {
        workspace: String,
        #[arg(long)]
        branch: String,
        /// Do not copy non-repo root files/directories into the workspace root
        #[arg(long, default_value_t = false)]
        no_copy_root: bool,
    },
    /// List known workspaces
    List,
    /// Re-discover direct-child repos and refresh manifest metadata
    Refresh {
        /// Show drift only without writing manifest
        #[arg(long)]
        check: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show workspace status
    Status {
        workspace: Option<String>,
        /// Show only repos with changes
        #[arg(long)]
        changed: bool,
        /// Print condensed totals instead of per-repo lines
        #[arg(long)]
        summary: bool,
        #[arg(long)]
        json: bool,
    },
    /// Commit staged or tracked changes across all repos in a workspace
    Commit {
        workspace: Option<String>,
        #[arg(short = 'm', long, required_unless_present = "dry_run")]
        message: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Push ahead commits for repos in a workspace
    Push {
        workspace: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove a workspace and its worktrees
    Remove {
        workspace: String,
        #[arg(long)]
        force: bool,
    },
    /// Prune stale git worktree metadata and reconcile state
    Prune,
    /// Validate metadata and detect inconsistencies
    Doctor {
        #[arg(long)]
        fix: bool,
        #[arg(long)]
        json: bool,
    },
}
