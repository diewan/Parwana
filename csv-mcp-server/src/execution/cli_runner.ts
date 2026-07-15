/**
 * CLI execution engine for CSV MCP Server.
 *
 * Spawns the csv-cli binary as a child process with proper
 * environment isolation, timeout handling, and output capture.
 */

import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

export function resolveCsvBinary(): string {
  if (process.env.CSV_BIN) return process.env.CSV_BIN;
  const localBin = path.resolve(__dirname, '../../../target/release/csv');
  try {
    fs.accessSync(localBin, fs.constants.X_OK);
    return localBin;
  } catch {
    return 'csv';
  }
}

const CSV_BIN = resolveCsvBinary();

export async function executeCsvCommand(
  args: string[],
  opts: { timeoutMs?: number; agentId: string; toolName: string }
): Promise<CliResult> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const child = spawn(CSV_BIN, args, {
      env: {
        ...process.env,
        RUST_LOG: 'info',
        CSV_AGENT_ID: opts.agentId,
        CSV_AGENT_TOOL: opts.toolName,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    if (!child.stdout || !child.stderr) {
      reject(new Error('CSV CLI process was started without captured output pipes'));
      return;
    }
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`CSV CLI timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code ?? 1,
        durationMs: Date.now() - start,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export function parseCliOutput(raw: string): unknown {
  if (!raw) return { message: '(empty output)' };
  try {
    return JSON.parse(raw);
  } catch {
    return { message: raw };
  }
}
