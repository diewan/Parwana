/**
 * Structured audit logger for CSV MCP Server.
 *
 * Every agent-originated state change is logged here as JSON Lines
 * to stderr so it is captured by the process supervisor without
 * polluting MCP stdout.
 */

import * as crypto from 'crypto';

export interface AuditEntry {
  ts: string;
  session_id: string;
  tool: string;
  phase: 'before' | 'after';
  args_hash?: string;
  result_hash?: string;
  duration_ms?: number;
  exit_code?: number;
  error?: string;
}

export function auditLog(entry: AuditEntry): void {
  process.stderr.write(JSON.stringify(entry) + '\n');
}

export function hashForAudit(data: unknown): string {
  const bytes = Buffer.from(JSON.stringify(data));
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
