// Copyright 2020-2023 The Jujutsu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::slice;

use clap_complete::ArgValueCandidates;
use itertools::Itertools as _;
use jj_lib::graph::GraphEdge;
use jj_lib::graph::reverse_graph;
use jj_lib::op_store::OpStoreError;
use jj_lib::op_walk;
use jj_lib::operation::Operation;
use jj_lib::repo::RepoLoader;

use super::diff::show_op_diff;
use crate::cli_util::CommandHelper;
use crate::cli_util::LogContentFormat;
use crate::cli_util::WorkspaceCommandEnvironment;
use crate::cli_util::format_template;
use crate::command_error::CommandError;
use crate::complete;
use crate::diff_util::DiffFormatArgs;
use crate::diff_util::DiffRenderer;
use crate::diff_util::diff_formats_for_log;
use crate::formatter::Formatter;
use crate::graphlog::GraphStyle;
use crate::graphlog::get_graphlog;
use crate::operation_templater::OperationTemplateLanguage;
use crate::templater::TemplateRenderer;
use crate::ui::Ui;

/// Make an operation part of the operation log
///
/// Sometimes an operation does not make it into the operation log for some
/// reason. This command can then be used for making that operation part of the
/// operation log.
///
/// Running this command on an operation that is already in the operation log
/// (`jj op log`) has no effect.
#[derive(clap::Args, Clone, Debug)]
pub struct OperationIntegrateArgs {
    /// The operation to integrate
    operation: String,
}

pub fn cmd_op_integrate(
    ui: &mut Ui,
    command: &CommandHelper,
    args: &OperationIntegrateArgs,
) -> Result<(), CommandError> {
    let mut workspace_command = command.workspace_helper(ui)?;
    let target_op = workspace_command.resolve_single_op(&args.operation)?;
    let op_heads_store = workspace_command.repo().op_heads_store();
    op_heads_store.update_op_heads(target_op.parent_ids(), target_op.id())?;

    Ok(())
}
