/**
 * Cordon Cryptographic Core — WebCrypto HMAC-SHA256 & Audit Integrity
 * Bietet authentische kryptografische Vorwärtsverkettung und DPAPI-Schutz-Simulation.
 */

import { AuditRecord } from '../types/cordon';

// Deterministic canonical string representation
export function canonicalize(obj: Record<string, any>): string {
  const sortedKeys = Object.keys(obj).sort();
  const sortedObj: Record<string, any> = {};
  for (const k of sortedKeys) {
    const val = obj[k];
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      sortedObj[k] = JSON.parse(canonicalize(val));
    } else {
      sortedObj[k] = val;
    }
  }
  return JSON.stringify(sortedObj);
}

// Fixed or derived simulated DPAPI key (32 bytes)
const MASTER_DPAPI_ENTROPY = new Uint8Array([
  0x43, 0x4f, 0x52, 0x44, 0x4f, 0x4e, 0x5f, 0x44, 
  0x50, 0x41, 0x50, 0x49, 0x5f, 0x4c, 0x4f, 0x43, 
  0x41, 0x4c, 0x4d, 0x41, 0x43, 0x48, 0x49, 0x4e, 
  0x45, 0x5f, 0x4b, 0x45, 0x59, 0x32, 0x35, 0x36
]);

let cryptoKeyPromise: Promise<CryptoKey> | null = null;

export async function getDpapiMasterKey(): Promise<CryptoKey> {
  if (!cryptoKeyPromise) {
    cryptoKeyPromise = window.crypto.subtle.importKey(
      'raw',
      MASTER_DPAPI_ENTROPY,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }
  return cryptoKeyPromise;
}

export async function computeHmacSha256(prevHmac: string, dataString: string): Promise<string> {
  const key = await getDpapiMasterKey();
  const encoder = new TextEncoder();
  const combined = `${prevHmac}|${dataString}`;
  const signature = await window.crypto.subtle.sign('HMAC', key, encoder.encode(combined));
  
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface VerificationResult {
  valid: boolean;
  totalRecords: number;
  brokenIndex?: number;
  expectedHmac?: string;
  actualHmac?: string;
}

export async function verifyAuditChain(records: AuditRecord[]): Promise<VerificationResult> {
  if (records.length === 0) {
    return { valid: true, totalRecords: 0 };
  }

  let expectedPrev = '0000000000000000000000000000000000000000000000000000000000000000';

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    // Check prev link pointer
    if (rec.prevHmac !== expectedPrev) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenIndex: i,
        expectedHmac: expectedPrev,
        actualHmac: rec.prevHmac,
      };
    }

    // Recompute current HMAC from canonical content
    const canonicalContent = canonicalize({
      index: rec.index,
      timestamp: rec.timestamp,
      eventType: rec.eventType,
      agentId: rec.agentId,
      details: rec.details,
    });

    const calculatedHmac = await computeHmacSha256(rec.prevHmac, canonicalContent);

    if (calculatedHmac !== rec.hmac) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenIndex: i,
        expectedHmac: calculatedHmac,
        actualHmac: rec.hmac,
      };
    }

    expectedPrev = calculatedHmac;
  }

  return { valid: true, totalRecords: records.length };
}

// Formats a byte array or string into clean hexadecimal inspection columns
export function formatHexDump(buffer: Uint8Array): { hex: string; ascii: string; offset: string }[] {
  const rows: { hex: string; ascii: string; offset: string }[] = [];
  const chunkSize = 16;

  for (let i = 0; i < buffer.length; i += chunkSize) {
    const slice = buffer.slice(i, i + chunkSize);
    const hexParts: string[] = [];
    let asciiPart = '';

    for (let j = 0; j < chunkSize; j++) {
      if (j < slice.length) {
        const byte = slice[j];
        hexParts.push(byte.toString(16).padStart(2, '0').toUpperCase());
        asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '·';
      } else {
        hexParts.push('  ');
      }
    }

    const offset = i.toString(16).padStart(4, '0').toUpperCase();
    const hex = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ');
    rows.push({ offset, hex, ascii: asciiPart });
  }

  return rows;
}
