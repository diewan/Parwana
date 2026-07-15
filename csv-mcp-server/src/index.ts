#!/usr/bin/env node
/**
 * CSV MCP Server — AI Agent Integration
 *
 * Enables AI agents (Claude, GPT-4, LangChain, AutoGPT, custom agents) to
 * operate Parwana workflows through the Model Context Protocol (MCP).
 *
 * SECURITY CONTRACT:
 *   - No tool bypasses TransferCoordinator.
 *   - No tool fabricates proofs, seals, or chain state.
 *   - All inputs are Zod-validated before CLI invocation.
 *   - Every mutating call is audit-logged before and after execution.
 *   - Proof bundle bytes are never constructed in this layer.
 *
 * Usage:
 *   csv-mcp                    # Read-only protocol inspector (stdio)
 *   csv-mcp --legacy-mutations # Explicit legacy compatibility surface
 *   csv-mcp --sse --port 3000  # SSE transport on port 3000
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { z } from 'zod';
import * as crypto from 'crypto';

// ── Internal modules ────────────────────────────────────────────────────────
import {
  CreateSealInput,
  TransferSanadInput,
  VerifyProofInput,
  GetSanadsInput,
  MonitorTransferInput,
  ExportProofBundleInput,
  AcceptConsignmentInput,
  GetProtocolInfoInput,
} from './validation/schemas.js';

import { auditLog, hashForAudit } from './audit/logger.js';
import { executeCsvCommand, parseCliOutput } from './execution/cli_runner.js';
import { writeTempJson, deleteTempFile } from './execution/temp_files.js';

// ─────────────────────────────────────────────────────────────────────────────
// MCP Server setup
// ─────────────────────────────────────────────────────────────────────────────

async function startServer(
  transport: 'stdio' | 'sse' = 'stdio',
  port = 3000,
  legacyMutations = false
): Promise<void> {
  const server = new McpServer({
    name: legacyMutations ? 'csv-protocol-legacy-mutations' : 'csv-protocol-inspector',
    version: '1.0.0',
  });

  // Default discovery is namespaced and read-only. The old unprefixed names
  // exist only in the explicitly selected legacy compatibility mode.
  const exposedName = (name: string): string =>
    legacyMutations ? name : `csv_protocol_${name}`;

  // Derive a session ID at startup; all audit entries for this process share it
  const SESSION_ID = crypto.randomUUID();

  // ── Helper: wrap every tool handler with audit + Zod validation ──────────

  function wrapTool<TInput>(
    toolName: string,
    schema: z.ZodType<TInput>,
    handler: (input: TInput, agentId: string) => Promise<unknown>
  ) {
    return async (rawInput: unknown): Promise<{ content: Array<{ type: 'text'; text: string }> }> => {
      const agentId = SESSION_ID;

      // 1. Validate
      const parsed = schema.safeParse(rawInput);
      if (!parsed.success) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: 'VALIDATION_ERROR',
              details: parsed.error.flatten(),
            }),
          }],
        };
      }

      // 2. Pre-execution audit
      auditLog({
        ts: new Date().toISOString(),
        session_id: agentId,
        tool: toolName,
        phase: 'before',
        args_hash: hashForAudit(parsed.data),
      });

      const execStart = Date.now();

      try {
        const result = await handler(parsed.data, agentId);

        // 3. Post-execution audit
        auditLog({
          ts: new Date().toISOString(),
          session_id: agentId,
          tool: toolName,
          phase: 'after',
          result_hash: hashForAudit(result),
          duration_ms: Date.now() - execStart,
          exit_code: 0,
        });

        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);

        auditLog({
          ts: new Date().toISOString(),
          session_id: agentId,
          tool: toolName,
          phase: 'after',
          duration_ms: Date.now() - execStart,
          exit_code: 1,
          error: message,
        });

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ error: 'EXECUTION_ERROR', message }),
          }],
        };
      }
    };
  }

  // ── Tool: create_seal ────────────────────────────────────────────────────

  if (legacyMutations) server.tool(
    'create_seal',
    'Create a new single-use cryptographic seal on a specified blockchain. Returns seal_id and transaction details.',
    { chain: z.string(), value: z.number(), memo: z.string().optional() },
    wrapTool('create_seal', CreateSealInput, async (input, agentId) => {
      const args = [
        'seals', 'create',
        '--chain', input.chain,
        '--value', String(input.value),
        ...(input.memo ? ['--memo', input.memo] : []),
        '--output', 'json',
      ];
      const result = await executeCsvCommand(args, { agentId, toolName: 'create_seal' });
      if (result.exitCode !== 0) {
        throw new Error(`CLI failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: transfer_sanad ─────────────────────────────────────────────────

  if (legacyMutations) server.tool(
    'transfer_sanad',
    'Execute a cross-chain transfer of a sanad. Uses TransferCoordinator; never calls adapters directly. On failure, returns structured error — caller must not auto-retry.',
    {
      sanad_id: z.string(),
      destination_chain: z.string(),
      destination: z.string(),
      dry_run: z.boolean().optional(),
    },
    wrapTool('transfer_sanad', TransferSanadInput, async (input, agentId) => {
      const args = [
        'cross-chain', 'transfer',
        '--sanad-id', input.sanad_id,
        '--destination-chain', input.destination_chain,
        '--destination', input.destination,
        ...(input.dry_run ? ['--dry-run'] : []),
        '--output', 'json',
      ];
      // Transfers get a generous 5-minute timeout (finality waits vary by chain)
      const result = await executeCsvCommand(args, {
        agentId,
        toolName: 'transfer_sanad',
        timeoutMs: 300_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(`Transfer failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: verify_proof ───────────────────────────────────────────────────

  server.tool(
    exposedName('verify_proof'),
    'Verify a proof bundle. Returns verification_level — callers must not rely solely on is_valid for minting decisions.',
    {
      bundle_json: z.string(),
      expected_sanad_id: z.string().optional(),
      expected_chain: z.string().optional(),
    },
    wrapTool('verify_proof', VerifyProofInput, async (input, agentId) => {
      const tmpFile = await writeTempJson(input.bundle_json);
      try {
        const args = [
          'validate', 'proof',
          '--bundle-file', tmpFile,
          ...(input.expected_sanad_id ? ['--expected-sanad-id', input.expected_sanad_id] : []),
          ...(input.expected_chain ? ['--expected-chain', input.expected_chain] : []),
          '--output', 'json',
        ];
        const result = await executeCsvCommand(args, {
          agentId,
          toolName: 'verify_proof',
          timeoutMs: 10_000,
        });
        // verify_proof is a read-only operation; non-zero exit means invalid proof,
        // not an execution error — surface the structured result either way.
        return parseCliOutput(result.stdout || result.stderr);
      } finally {
        await deleteTempFile(tmpFile);
      }
    })
  );

  // ── Tool: get_sanads ─────────────────────────────────────────────────────

  server.tool(
    exposedName('get_sanads'),
    'List sanads for an address. Returns opaque value fields — use classify_sanad for semantic enrichment.',
    {
      address: z.string(),
      chain: z.string().optional(),
      limit: z.number().optional(),
      offset: z.number().optional(),
      status: z.string().optional(),
    },
    wrapTool('get_sanads', GetSanadsInput, async (input, agentId) => {
      const args = [
        'sanads', 'list',
        '--address', input.address,
        '--limit', String(input.limit),
        '--offset', String(input.offset),
        '--status', input.status ?? 'all',
        ...(input.chain ? ['--chain', input.chain] : []),
        '--output', 'json',
      ];
      const result = await executeCsvCommand(args, {
        agentId,
        toolName: 'get_sanads',
        timeoutMs: 10_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(`CLI failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: monitor_transfer ───────────────────────────────────────────────

  server.tool(
    exposedName('monitor_transfer'),
    'Poll the status of a cross-chain transfer. "compromised" and "rolled_back" states require human review.',
    { transfer_id: z.string() },
    wrapTool('monitor_transfer', MonitorTransferInput, async (input, agentId) => {
      const args = [
        'cross-chain', 'status',
        '--transfer-id', input.transfer_id,
        '--output', 'json',
      ];
      const result = await executeCsvCommand(args, {
        agentId,
        toolName: 'monitor_transfer',
        timeoutMs: 10_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(`CLI failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: export_proof_bundle ────────────────────────────────────────────

  server.tool(
    exposedName('export_proof_bundle'),
    'Export a complete proof bundle for offline verification or agent-to-agent handoff.',
    {
      transfer_id: z.string(),
      format: z.enum(['json', 'hex', 'base64']).optional(),
      include_provenance: z.boolean().optional(),
    },
    wrapTool('export_proof_bundle', ExportProofBundleInput, async (input, agentId) => {
      const args = [
        'proofs', 'export',
        '--transfer-id', input.transfer_id,
        '--format', input.format ?? 'json',
        ...(input.include_provenance ? ['--include-provenance'] : []),
        '--output', 'json',
      ];
      const result = await executeCsvCommand(args, {
        agentId,
        toolName: 'export_proof_bundle',
        timeoutMs: 15_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(`CLI failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: accept_consignment ─────────────────────────────────────────────

  if (legacyMutations) server.tool(
    'accept_consignment',
    'Accept and validate an incoming state transition consignment from a counterparty.',
    {
      consignment_json: z.string(),
      expected_sanad_id: z.string().optional(),
      strict: z.boolean().optional(),
    },
    wrapTool('accept_consignment', AcceptConsignmentInput, async (input, agentId) => {
      const tmpFile = await writeTempJson(input.consignment_json);
      try {
        const args = [
          'validate', 'consignment',
          '--consignment-file', tmpFile,
          ...(input.expected_sanad_id ? ['--expected-sanad-id', input.expected_sanad_id] : []),
          ...(input.strict ? ['--strict'] : []),
          '--output', 'json',
        ];
        const result = await executeCsvCommand(args, {
          agentId,
          toolName: 'accept_consignment',
          timeoutMs: 15_000,
        });
        return parseCliOutput(result.stdout || result.stderr);
      } finally {
        await deleteTempFile(tmpFile);
      }
    })
  );

  // ── Tool: get_protocol_info ──────────────────────────────────────────────

  server.tool(
    exposedName('get_protocol_info'),
    'Return current protocol version and chain adapter status. Use before transfers to verify compatibility.',
    { chain: z.string().optional() },
    wrapTool('get_protocol_info', GetProtocolInfoInput, async (input, agentId) => {
      const args = [
        'chain', 'info',
        ...(input.chain && input.chain !== 'all' ? ['--chain', input.chain] : []),
        '--output', 'json',
      ];
      const result = await executeCsvCommand(args, {
        agentId,
        toolName: 'get_protocol_info',
        timeoutMs: 10_000,
      });
      if (result.exitCode !== 0) {
        throw new Error(`CLI failed: ${result.stderr}`);
      }
      return parseCliOutput(result.stdout);
    })
  );

  // ── Tool: health_check ───────────────────────────────────────────────────

  server.tool(
    exposedName('health_check'),
    'Verify that the MCP server and CSV CLI are operational.',
    {},
    async () => {
      try {
        const result = await executeCsvCommand(['--version'], {
          agentId: SESSION_ID,
          toolName: 'health_check',
          timeoutMs: 5_000,
        });
        const healthy = result.exitCode === 0;
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              mcp_server: 'ok',
              cli_binary: healthy ? 'ok' : 'error',
              cli_version: healthy ? result.stdout : null,
              runtime: 'unknown',
              timestamp: new Date().toISOString(),
              error: healthy ? null : result.stderr,
            }),
          }],
        };
      } catch (err: unknown) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({
              mcp_server: 'ok',
              cli_binary: 'error',
              cli_version: null,
              runtime: 'unknown',
              timestamp: new Date().toISOString(),
              error: err instanceof Error ? err.message : String(err),
            }),
          }],
        };
      }
    }
  );

  // ── Transport ────────────────────────────────────────────────────────────

  if (transport === 'stdio') {
    const t = new StdioServerTransport();
    await server.connect(t);
  } else {
    const express = (await import('express')).default;
    const app = express();
    app.get('/sse', (req, res) => {
      const t = new SSEServerTransport('/message', res);
      server.connect(t);
    });
    app.listen(port, () => {
      process.stderr.write(`CSV MCP Server listening on port ${port}\n`);
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const useSSE = args.includes('--sse');
const portArg = args.find(a => a.startsWith('--port='));
const port = portArg ? parseInt(portArg.split('=')[1], 10) : 3000;
const legacyMutations = args.includes('--legacy-mutations');

startServer(useSSE ? 'sse' : 'stdio', port, legacyMutations).catch((err) => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
