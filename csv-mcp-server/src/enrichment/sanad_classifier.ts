/**
 * Non-canonical AI enrichment for sanad payloads.
 *
 * CONSTRAINTS (from audit.md):
 *   - Outputs are signed, versioned, and attributable.
 *   - Outputs must never influence canonical proof paths.
 *   - Results are revocable; downstream systems must treat them as advisory.
 *   - AI may assist: extraction, classification, schema mapping, tagging.
 *   - AI must NEVER define: hashes, commitments, proofs, seal consumption.
 */

export interface SanadClassification {
  sanad_id: string;
  classifier_version: string;     // semver of this module
  schema_suggestion: string | null;
  semantic_tags: string[];
  confidence: number;             // 0.0 – 1.0
  attribution: {
    model: string;
    timestamp: string;
    revocable: true;              // always true; this is non-canonical
    non_authoritative: true;      // always true
  };
}

/**
 * Classify a sanad payload semantically using pattern matching.
 * Does not make network calls. Does not modify protocol state.
 *
 * @param sanadId  - 64-char hex sanad identifier
 * @param opaqueValue - raw value field from GetSanadsResult (treated as opaque string)
 * @returns SanadClassification with confidence score and advisory tags
 */
export function classifySanad(
  sanadId: string,
  opaqueValue: string | null
): SanadClassification {
  // Pattern-based heuristics — never authoritative
  const tags: string[] = [];
  let schema: string | null = null;
  let confidence = 0.0;

  if (opaqueValue) {
    try {
      const parsed = JSON.parse(opaqueValue);
      if (typeof parsed === 'object' && parsed !== null) {
        if ('type' in parsed) {
          tags.push(`type:${parsed.type}`);
          confidence += 0.4;
        }
        if ('schema' in parsed) {
          schema = String(parsed.schema);
          confidence += 0.4;
        }
        if ('amount' in parsed && 'currency' in parsed) {
          tags.push('category:financial-asset');
          confidence += 0.2;
        }
        if ('credential_type' in parsed) {
          tags.push('category:credential');
          confidence += 0.2;
        }
      }
    } catch {
      // Opaque binary or non-JSON — classify as unknown
      tags.push('encoding:non-json');
    }
  }

  return {
    sanad_id: sanadId,
    classifier_version: '1.0.0',
    schema_suggestion: schema,
    semantic_tags: tags,
    confidence: Math.min(confidence, 1.0),
    attribution: {
      model: 'csv-mcp-heuristic-v1',
      timestamp: new Date().toISOString(),
      revocable: true,
      non_authoritative: true,
    },
  };
}
