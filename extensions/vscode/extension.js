'use strict';
// VS Code glue for the OpenCobot daemon client (client.js).
//
// Thin by design: this file only wires VS Code commands to the
// protocol client and shows results in an output channel. No model
// calls, no file writes, no policy decisions here — the daemon
// decides, this file displays.

const vscode = require('vscode');
const client = require('./client');

const OUTPUT_CHANNEL = 'OpenCobot';

function stateDir() {
  const configured = vscode.workspace
    .getConfiguration('opencobot')
    .get('stateDir');
  return configured || client.defaultStateDir();
}

function workspaceFolder() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return undefined;
  }
  return folders[0].uri.fsPath;
}

function capabilityToken(workspace) {
  // The daemon's tool calls inside a run are scoped to this folder.
  return { folders: [workspace] };
}

function summarizeRun(out, run) {
  out.appendLine(`run ${run.run_id}: ok=${run.ok}`);
  out.appendLine(`  integrated: ${(run.integrated || []).join(', ') || '(none)'}`);
  out.appendLine(`  done: ${(run.done || []).join(', ') || '(none)'}`);
  out.appendLine(`  failed: ${(run.failed || []).join(', ') || '(none)'}`);
  out.appendLine(`  queued: ${(run.queued || []).join(', ') || '(none)'}`);
  out.appendLine(`  needs_approval: ${(run.needs_approval || []).join(', ') || '(none)'}`);
  if (run.error) {
    out.appendLine(`  error: ${run.error}`);
  }
}

async function runTask() {
  const out = vscode.window.createOutputChannel(OUTPUT_CHANNEL);
  const task = await vscode.window.showInputBox({
    prompt: 'Task for the OpenCobot orchestrator',
    placeHolder: 'e.g. Add a --json flag to the status command',
    ignoreFocusOut: true,
  });
  if (!task) {
    return;
  }
  const workspace = workspaceFolder();
  if (!workspace) {
    vscode.window.showErrorMessage(
      'OpenCobot: open a workspace folder first — a run needs a workspace.');
    return;
  }
  out.show(true);
  out.appendLine(`OpenCobot: running ${JSON.stringify(task)} ...`);
  out.appendLine('This can take a few minutes (model calls). Do not start a second run for the same task.');
  try {
    const reply = await client.orchestratorRun(stateDir(), {
      task,
      workspace,
      token: capabilityToken(workspace),
    });
    if (!reply.ok) {
      out.appendLine(`daemon refused the run: ${reply.error}`);
      vscode.window.showErrorMessage(`OpenCobot: ${reply.error}`);
      return;
    }
    summarizeRun(out, reply.run);
    if (!reply.run.ok) {
      vscode.window.showWarningMessage(
        `OpenCobot: run ${reply.run.run_id} finished with failures — see the OpenCobot output channel.`);
    } else {
      vscode.window.showInformationMessage(
        `OpenCobot: run ${reply.run.run_id} finished.`);
    }
  } catch (err) {
    out.appendLine(`error: ${err.message}`);
    vscode.window.showErrorMessage(`OpenCobot: ${err.message}`);
  }
}

async function showLastRun() {
  const out = vscode.window.createOutputChannel(OUTPUT_CHANNEL);
  const workspace = workspaceFolder();
  if (!workspace) {
    vscode.window.showErrorMessage(
      'OpenCobot: open a workspace folder first — status is per project.');
    return;
  }
  const project = workspace.split(/[\\/]/).filter(Boolean).pop();
  out.show(true);
  try {
    const reply = await client.orchestratorStatus(stateDir(), { project });
    if (!reply.ok) {
      out.appendLine(`no stored run: ${reply.error}`);
      vscode.window.showInformationMessage(`OpenCobot: ${reply.error}`);
      return;
    }
    out.appendLine(`OpenCobot: last run for project ${project}:`);
    summarizeRun(out, reply.run.summary || reply.run);
  } catch (err) {
    out.appendLine(`error: ${err.message}`);
    vscode.window.showErrorMessage(`OpenCobot: ${err.message}`);
  }
}

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('opencobot.runTask', runTask),
    vscode.commands.registerCommand('opencobot.showLastRun', showLastRun),
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
