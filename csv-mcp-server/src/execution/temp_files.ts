/**
 * Temp file helpers for proof bundles and consignments.
 *
 * Bundle JSON and consignment data must be written to temp files
 * (never passed via shell arguments) to prevent injection.
 * Temp files are deleted on both success and failure paths.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

export async function writeTempJson(content: string): Promise<string> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-mcp-'));
  const filePath = path.join(tmpDir, 'payload.json');
  await fs.writeFile(filePath, content, 'utf8');
  return filePath;
}

export async function deleteTempFile(filePath: string): Promise<void> {
  try {
    await fs.unlink(filePath);
    await fs.rmdir(path.dirname(filePath));
  } catch {
    // Best-effort cleanup; do not surface to caller
  }
}
