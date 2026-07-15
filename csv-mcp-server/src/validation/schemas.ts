/**
 * Zod input validation schemas for CSV MCP Server tools.
 *
 * These schemas are the single source of truth for input validation.
 * All tool handlers must validate their inputs against these schemas
 * before invoking the CSV CLI.
 */

import { z } from 'zod';

export const VALID_CHAINS = ['bitcoin', 'ethereum', 'solana', 'sui', 'aptos'] as const;
export type ValidChain = (typeof VALID_CHAINS)[number];

const ChainEnum = z.enum(VALID_CHAINS);
export const HexId64 = z.string().regex(/^[0-9a-f]{64}$/, 'Must be 64 lowercase hex chars (32 bytes)');
export const Address = z.string().min(20).max(128).regex(/^(0x)?[0-9a-fA-F]+$/, 'Must be a hex address');

export const CreateSealInput = z.object({
  chain: ChainEnum,
  value: z.number().positive().finite(),
  memo: z.string().max(256).optional(),
});

export const TransferSanadInput = z.object({
  sanad_id: HexId64,
  destination_chain: ChainEnum,
  destination: Address,
  dry_run: z.boolean().default(false),
});

export const VerifyProofInput = z.object({
  bundle_json: z.string().min(1).refine(
    (s) => { try { JSON.parse(s); return true; } catch { return false; } },
    { message: 'bundle_json must be valid JSON' }
  ),
  expected_sanad_id: HexId64.optional(),
  expected_chain: ChainEnum.optional(),
});

export const GetSanadsInput = z.object({
  address: z.string().min(20).max(128),
  chain: ChainEnum.optional(),
  limit: z.number().int().positive().max(100).default(20),
  offset: z.number().int().nonnegative().default(0),
  status: z.enum(['active', 'consumed', 'locked', 'all']).default('all'),
});

export const MonitorTransferInput = z.object({
  transfer_id: HexId64,
});

export const ExportProofBundleInput = z.object({
  transfer_id: HexId64,
  format: z.enum(['json', 'hex', 'base64']).default('json'),
  include_provenance: z.boolean().default(true),
});

export const AcceptConsignmentInput = z.object({
  consignment_json: z.string().min(1).refine(
    (s) => {
      try {
        const parsed: unknown = JSON.parse(s);
        return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed);
      }
      catch { return false; }
    },
    { message: 'consignment_json must be a JSON object' }
  ),
  expected_sanad_id: HexId64.optional(),
  strict: z.boolean().default(true),
});

export const GetProtocolInfoInput = z.object({
  chain: z.enum([...VALID_CHAINS, 'all'] as const).default('all'),
});

export type CreateSealInputType = z.infer<typeof CreateSealInput>;
export type TransferSanadInputType = z.infer<typeof TransferSanadInput>;
export type VerifyProofInputType = z.infer<typeof VerifyProofInput>;
export type GetSanadsInputType = z.infer<typeof GetSanadsInput>;
export type MonitorTransferInputType = z.infer<typeof MonitorTransferInput>;
export type ExportProofBundleInputType = z.infer<typeof ExportProofBundleInput>;
export type AcceptConsignmentInputType = z.infer<typeof AcceptConsignmentInput>;
export type GetProtocolInfoInputType = z.infer<typeof GetProtocolInfoInput>;
