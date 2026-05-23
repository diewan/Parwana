import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  CreateSealInput,
  TransferSanadInput,
  VerifyProofInput,
  GetSanadsInput,
  MonitorTransferInput,
  ExportProofBundleInput,
  AcceptConsignmentInput,
  GetProtocolInfoInput,
} from '../src/validation/schemas';

describe('CreateSealInput validation', () => {
  it('accepts valid input', () => {
    expect(CreateSealInput.safeParse({ chain: 'ethereum', value: 1.5 }).success).toBe(true);
  });
  it('rejects zero value', () => {
    expect(CreateSealInput.safeParse({ chain: 'bitcoin', value: 0 }).success).toBe(false);
  });
  it('rejects negative value', () => {
    expect(CreateSealInput.safeParse({ chain: 'solana', value: -1 }).success).toBe(false);
  });
  it('rejects unknown chain', () => {
    expect(CreateSealInput.safeParse({ chain: 'dogecoin', value: 1 }).success).toBe(false);
  });
});

describe('TransferSanadInput validation', () => {
  const validId = 'a'.repeat(64);
  it('rejects non-hex sanad_id', () => {
    expect(TransferSanadInput.safeParse({
      sanad_id: 'GGGG' + 'a'.repeat(60),
      destination_chain: 'ethereum',
      destination: '0x' + 'a'.repeat(40),
    }).success).toBe(false);
  });
  it('rejects short sanad_id', () => {
    expect(TransferSanadInput.safeParse({
      sanad_id: 'abc',
      destination_chain: 'solana',
      destination: '0x' + 'b'.repeat(40),
    }).success).toBe(false);
  });
  it('accepts valid input', () => {
    expect(TransferSanadInput.safeParse({
      sanad_id: validId,
      destination_chain: 'solana',
      destination: 'b'.repeat(44),
    }).success).toBe(true);
  });
});

describe('VerifyProofInput validation', () => {
  it('rejects invalid JSON', () => {
    expect(VerifyProofInput.safeParse({ bundle_json: '{broken' }).success).toBe(false);
  });
  it('accepts valid JSON', () => {
    expect(VerifyProofInput.safeParse({ bundle_json: '{"a":1}' }).success).toBe(true);
  });
});

describe('GetSanadsInput validation', () => {
  it('accepts valid input with defaults', () => {
    const result = GetSanadsInput.safeParse({ address: '0x' + 'a'.repeat(40) });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(20);
      expect(result.data.offset).toBe(0);
      expect(result.data.status).toBe('all');
    }
  });
  it('rejects address too short', () => {
    expect(GetSanadsInput.safeParse({ address: 'abc' }).success).toBe(false);
  });
  it('accepts limit max', () => {
    expect(GetSanadsInput.safeParse({
      address: '0x' + 'a'.repeat(40),
      limit: 100,
    }).success).toBe(true);
  });
  it('rejects limit over max', () => {
    expect(GetSanadsInput.safeParse({
      address: '0x' + 'a'.repeat(40),
      limit: 101,
    }).success).toBe(false);
  });
});

describe('MonitorTransferInput validation', () => {
  it('accepts valid 64-char hex transfer_id', () => {
    expect(MonitorTransferInput.safeParse({
      transfer_id: 'b'.repeat(64),
    }).success).toBe(true);
  });
  it('rejects non-hex transfer_id', () => {
    expect(MonitorTransferInput.safeParse({
      transfer_id: 'ZZZZ' + 'b'.repeat(60),
    }).success).toBe(false);
  });
});

describe('ExportProofBundleInput validation', () => {
  it('accepts valid input with defaults', () => {
    const result = ExportProofBundleInput.safeParse({
      transfer_id: 'c'.repeat(64),
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.format).toBe('json');
      expect(result.data.include_provenance).toBe(true);
    }
  });
  it('accepts explicit format', () => {
    expect(ExportProofBundleInput.safeParse({
      transfer_id: 'd'.repeat(64),
      format: 'base64',
      include_provenance: false,
    }).success).toBe(true);
  });
});

describe('AcceptConsignmentInput validation', () => {
  it('accepts valid JSON object', () => {
    expect(AcceptConsignmentInput.safeParse({
      consignment_json: '{"key": "value"}',
    }).success).toBe(true);
  });
  it('rejects invalid JSON', () => {
    expect(AcceptConsignmentInput.safeParse({
      consignment_json: '{broken',
    }).success).toBe(false);
  });
  it('rejects JSON array', () => {
    expect(AcceptConsignmentInput.safeParse({
      consignment_json: '[1, 2, 3]',
    }).success).toBe(false);
  });
  it('accepts strict false', () => {
    expect(AcceptConsignmentInput.safeParse({
      consignment_json: '{"key": "value"}',
      strict: false,
    }).success).toBe(true);
  });
});

describe('GetProtocolInfoInput validation', () => {
  it('accepts "all" default', () => {
    const result = GetProtocolInfoInput.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.chain).toBe('all');
    }
  });
  it('accepts specific chain', () => {
    expect(GetProtocolInfoInput.safeParse({
      chain: 'bitcoin',
    }).success).toBe(true);
  });
  it('rejects unknown chain', () => {
    expect(GetProtocolInfoInput.safeParse({
      chain: 'dogecoin',
    }).success).toBe(false);
  });
});
