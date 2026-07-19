/**
 * Lease acquisition and lifecycle management for cross-chain transfers.
 *
 * The TransferCoordinator enforces lease ownership: a cross-chain transfer
 * must hold a valid Lease whose transfer_id matches the SanadId.
 * Leases expire; the agent must not cache them across retries.
 */

import { executeCsvCommand, parseCliOutput } from './cli_runner.js';

export interface Lease {
  token: string;
  sanad_id: string;
  acquired_at: string;
  expires_at: string;
}

/**
 * Acquire a lease for a cross-chain transfer.
 * The lease must be passed to the transfer command.
 *
 * @param sanadId - 64-char hex sanad identifier
 * @param ttl - Time-to-live in seconds (default: 120)
 */
export async function acquireLease(
  sanadId: string,
  ttl: number = 120
): Promise<Lease> {
  const result = await executeCsvCommand([
    'cross-chain', 'acquire-lease',
    '--sanad-id', sanadId,
    '--ttl', String(ttl),
    '--output', 'json',
  ], {
    agentId: process.env.CSV_AGENT_ID || 'unknown',
    toolName: 'acquire_lease',
    timeoutMs: 15_000,
  });

  if (result.exitCode !== 0) {
    throw new Error(`Lease acquisition failed (exit ${result.exitCode}): ${result.stderr}`);
  }

  const parsed = parseCliOutput(result.stdout);
  if (typeof parsed !== 'object' || parsed === null || !('token' in parsed)) {
    throw new Error(`Invalid lease response: ${result.stdout}`);
  }

  return parsed as Lease;
}

/**
 * Check if a lease is still valid.
 * Leases should not be cached across retries.
 */
export function isLeaseValid(lease: Lease): boolean {
  return new Date(lease.expires_at) > new Date();
}
