import type {
  AesDecryptParams,
  AesDecryptResult,
  AesEncryptResult,
  CryptoEncoding,
  CryptoEngineErrorCode,
  CryptoHashAlgorithm,
  EncodingResult,
  HashResult,
  HmacKeyFormat,
  HmacKeyMaterial,
  HmacSignResult,
  HmacVerifyResult,
  RandomBytesResult,
} from '../types/crypto.ts';

export const PBKDF2_ITERATIONS = 600_000;

export const CRYPTO_PASSPHRASE_MAX_LENGTH = 512;

export const AES_KEY_LENGTH_BITS = 256;
export const AES_KEY_LENGTH_BYTES = 32;
export const GCM_IV_LENGTH_BITS = 96;
export const GCM_IV_LENGTH_BYTES = 12;
export const GCM_TAG_LENGTH_BITS = 128;
export const GCM_TAG_LENGTH_BYTES = 16;
export const SALT_LENGTH_BYTES = 16;
export const AES_KEY_DERIVATION = `PBKDF2-HMAC-SHA256 (${PBKDF2_ITERATIONS} iterations)`;

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const BASE64_LOOKUP = (() => {
  const table = new Int16Array(256).fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
    table[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  table['='.charCodeAt(0)] = -2;
  return table;
})();

const HEX_TABLE = (() => {
  const table = new Array<string>(256);
  for (let i = 0; i < 256; i += 1) {
    table[i] = i.toString(16).padStart(2, '0');
  }
  return table;
})();

export const CRYPTO_CONSTANTS = {
  PBKDF2_ITERATIONS,
  CRYPTO_PASSPHRASE_MAX_LENGTH,
  AES_KEY_LENGTH_BITS,
  AES_KEY_LENGTH_BYTES,
  GCM_IV_LENGTH_BITS,
  GCM_IV_LENGTH_BYTES,
  GCM_TAG_LENGTH_BITS,
  GCM_TAG_LENGTH_BYTES,
  SALT_LENGTH_BYTES,
} as const;

export class CryptoEngineError extends Error {
  readonly code: CryptoEngineErrorCode;

  constructor(code: CryptoEngineErrorCode, message: string) {
    super(message);
    this.name = 'CryptoEngineError';
    this.code = code;
  }
}

function cryptoError(code: CryptoEngineErrorCode, message: string): never {
  throw new CryptoEngineError(code, message);
}

export function isWebCryptoSupported(): boolean {
  return (
    typeof globalThis.crypto === 'object' &&
    globalThis.crypto !== null &&
    typeof globalThis.crypto.getRandomValues === 'function' &&
    typeof globalThis.crypto.subtle === 'object' &&
    globalThis.crypto.subtle !== null &&
    typeof globalThis.crypto.subtle.digest === 'function'
  );
}

export function assertWebCryptoSupported(): void {
  if (!isWebCryptoSupported()) {
    cryptoError('UNSUPPORTED_BROWSER_CRYPTO', 'Web Crypto API is not supported in this browser or environment');
  }
}

function toBytes(data: ArrayBuffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

function asBufferSource(data: Uint8Array): BufferSource {
  return data as unknown as BufferSource;
}

export function utf8Encode(text: string): Uint8Array {
  return TEXT_ENCODER.encode(text);
}

export function utf8Decode(data: Uint8Array | ArrayBuffer): string {
  return TEXT_DECODER.decode(toBytes(data));
}

export function bytesToHex(data: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(data);
  let result = '';
  for (let i = 0; i < bytes.length; i += 1) {
    result += HEX_TABLE[bytes[i]];
  }
  return result;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    cryptoError('INVALID_HEX', 'Invalid hexadecimal input: odd number of characters');
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    cryptoError('INVALID_HEX', 'Invalid hexadecimal input: contains a non-hexadecimal character');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(data: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(data);
  let result = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const a = bytes[i];
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    result += BASE64_ALPHABET[a >> 2];
    result += BASE64_ALPHABET[((a & 3) << 4) | (b >> 4)];
    result += BASE64_ALPHABET[((b & 15) << 2) | (c >> 6)];
    result += BASE64_ALPHABET[c & 63];
  }
  const chunk = bytes.length - i;
  if (chunk === 1) {
    const a = bytes[i];
    result += BASE64_ALPHABET[a >> 2];
    result += BASE64_ALPHABET[(a & 3) << 4];
    result += '==';
  } else if (chunk === 2) {
    const a = bytes[i];
    const b = bytes[i + 1];
    result += BASE64_ALPHABET[a >> 2];
    result += BASE64_ALPHABET[((a & 3) << 4) | (b >> 4)];
    result += BASE64_ALPHABET[(b & 15) << 2];
    result += '=';
  }
  return result;
}

export function base64ToBytes(input: string): Uint8Array {
  if (input.length === 0) {
    return new Uint8Array(0);
  }
  if (input.length % 4 !== 0) {
    cryptoError('INVALID_BASE64', 'Invalid base64 input: length must be a multiple of 4');
  }
  const firstPad = input.indexOf('=');
  const paddingChars = firstPad === -1 ? 0 : input.length - firstPad;
  if (paddingChars === 1 || paddingChars === 2) {
    if (!/^[A-Za-z0-9+/]*={1,2}$/.test(input)) {
      cryptoError('INVALID_BASE64', 'Invalid base64 input: padding is only allowed at the end');
    }
  } else if (paddingChars !== 0) {
    cryptoError('INVALID_BASE64', 'Invalid base64 input: invalid padding');
  }
  const output = new Uint8Array((input.length / 4) * 3 - paddingChars);
  let outIndex = 0;
  for (let groupStart = 0; groupStart < input.length; groupStart += 4) {
    let value = 0;
    let groupPadding = 0;
    for (let j = 0; j < 4; j += 1) {
      const code = input.charCodeAt(groupStart + j);
      const sextet = code < 256 ? BASE64_LOOKUP[code] : -1;
      if (sextet === -2) {
        groupPadding += 1;
        value = value << 6;
        continue;
      }
      if (sextet < 0) {
        cryptoError('INVALID_BASE64', 'Invalid base64 input: contains a character outside the base64 alphabet');
      }
      value = (value << 6) | sextet;
    }
    if (groupPadding === 1) {
      if ((value & 0xff) !== 0) {
        cryptoError('INVALID_BASE64', 'Invalid base64 input: non-canonical padding bits');
      }
      output[outIndex] = (value >> 16) & 0xff;
      output[outIndex + 1] = (value >> 8) & 0xff;
      outIndex += 2;
    } else if (groupPadding === 2) {
      if ((value & 0xffff) !== 0) {
        cryptoError('INVALID_BASE64', 'Invalid base64 input: non-canonical padding bits');
      }
      output[outIndex] = (value >> 16) & 0xff;
      outIndex += 1;
    } else {
      output[outIndex] = (value >> 16) & 0xff;
      output[outIndex + 1] = (value >> 8) & 0xff;
      output[outIndex + 2] = value & 0xff;
      outIndex += 3;
    }
  }
  return output;
}

export function utf8ToBase64(text: string): string {
  return bytesToBase64(TEXT_ENCODER.encode(text));
}

export function base64ToUtf8(input: string): string {
  return TEXT_DECODER.decode(base64ToBytes(input));
}

export function utf8ToHex(text: string): string {
  return bytesToHex(TEXT_ENCODER.encode(text));
}

export function hexToUtf8(hex: string): string {
  return TEXT_DECODER.decode(hexToBytes(hex));
}

function assertEncoding(encoding: CryptoEncoding): void {
  if (encoding !== 'base64' && encoding !== 'hex') {
    cryptoError('INVALID_ARGUMENT', 'Unsupported encoding');
  }
}

export function encodeText(text: string, encoding: CryptoEncoding): EncodingResult {
  assertEncoding(encoding);
  return {
    operation: 'encode',
    encoding,
    data: encoding === 'base64' ? utf8ToBase64(text) : utf8ToHex(text),
    note: 'Encoding is not encryption; it provides no secrecy.',
  };
}

export function decodeText(data: string, encoding: CryptoEncoding): EncodingResult {
  assertEncoding(encoding);
  return {
    operation: 'decode',
    encoding,
    data: encoding === 'base64' ? base64ToUtf8(data) : hexToUtf8(data),
    note: 'Decoding reveals the original bytes; it is not decryption.',
  };
}

export function randomBytes(lengthBytes: number): Uint8Array {
  if (!Number.isInteger(lengthBytes) || lengthBytes < 0) {
    cryptoError('INVALID_ARGUMENT', 'Random byte length must be a non-negative integer');
  }
  assertWebCryptoSupported();
  const out = new Uint8Array(lengthBytes);
  crypto.getRandomValues(out);
  return out;
}

export function generateRandomBytes(lengthBytes: number): RandomBytesResult {
  const bytes = randomBytes(lengthBytes);
  return {
    lengthBytes: bytes.length,
    bytes,
    hex: bytesToHex(bytes),
    base64: bytesToBase64(bytes),
  };
}

const HASH_WEB_ALGORITHMS: Readonly<Record<CryptoHashAlgorithm, string>> = {
  sha256: 'SHA-256',
  sha512: 'SHA-512',
};

function assertHashAlgorithm(algorithm: CryptoHashAlgorithm): void {
  if (algorithm !== 'sha256' && algorithm !== 'sha512') {
    cryptoError('INVALID_ARGUMENT', 'Unsupported hash algorithm');
  }
}

export async function hashText(text: string, algorithm: CryptoHashAlgorithm): Promise<HashResult> {
  assertHashAlgorithm(algorithm);
  assertWebCryptoSupported();
  const data = TEXT_ENCODER.encode(text);
  const digest = await crypto.subtle.digest(HASH_WEB_ALGORITHMS[algorithm], data);
  const hex = bytesToHex(digest);
  return {
    operation: 'hash',
    algorithm,
    digest: hex,
    digestLengthBits: hex.length * 4,
    inputBytes: data.length,
    reversible: false,
  };
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string' || passphrase.length < 8) {
    cryptoError('INVALID_ARGUMENT', 'Passphrase must be at least 8 characters');
  }
  if (passphrase.length > CRYPTO_PASSPHRASE_MAX_LENGTH) {
    cryptoError(
      'PASSPHRASE_TOO_LONG',
      `Passphrase is too long; it must be at most ${CRYPTO_PASSPHRASE_MAX_LENGTH} characters`,
    );
  }
}

async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    asBufferSource(TEXT_ENCODER.encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: asBufferSource(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: AES_KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function aesEncrypt(plaintext: string, passphrase: string): Promise<AesEncryptResult> {
  assertPassphrase(passphrase);
  assertWebCryptoSupported();
  const salt = randomBytes(SALT_LENGTH_BYTES);
  const iv = randomBytes(GCM_IV_LENGTH_BYTES);
  const key = await deriveAesKey(passphrase, salt);
  let combined: Uint8Array;
  try {
    const raw = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv), tagLength: GCM_TAG_LENGTH_BITS },
      key,
      asBufferSource(TEXT_ENCODER.encode(plaintext)),
    );
    combined = new Uint8Array(raw);
  } catch {
    cryptoError('UNKNOWN_CIPHER_FAILURE', 'Encryption failed unexpectedly');
  }
  const body = combined.subarray(0, combined.length - GCM_TAG_LENGTH_BYTES);
  const tag = combined.subarray(combined.length - GCM_TAG_LENGTH_BYTES);
  return {
    operation: 'encrypt',
    algorithm: 'AES-256-GCM',
    keyDerivation: AES_KEY_DERIVATION,
    authTagBits: GCM_TAG_LENGTH_BITS,
    ciphertext: bytesToBase64(body),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    tag: bytesToBase64(tag),
    reversible: true,
  };
}

export async function aesDecrypt(params: AesDecryptParams): Promise<AesDecryptResult> {
  assertPassphrase(params.passphrase);
  assertWebCryptoSupported();
  let cipherBytes: Uint8Array;
  let salt: Uint8Array;
  let iv: Uint8Array;
  let tag: Uint8Array | null;
  try {
    cipherBytes = base64ToBytes(params.ciphertext);
    salt = base64ToBytes(params.salt);
    iv = base64ToBytes(params.iv);
    tag = params.tag === undefined ? null : base64ToBytes(params.tag);
  } catch (error) {
    if (error instanceof CryptoEngineError && error.code === 'INVALID_BASE64') {
      cryptoError('INVALID_AES_METADATA', 'Encrypted payload fields must be valid base64');
    }
    throw error;
  }
  if (salt.length !== SALT_LENGTH_BYTES || iv.length !== GCM_IV_LENGTH_BYTES) {
    cryptoError('INVALID_AES_METADATA', 'Invalid AES-GCM salt or IV length');
  }
  let combined: Uint8Array;
  if (tag === null) {
    combined = cipherBytes;
  } else {
    if (tag.length !== GCM_TAG_LENGTH_BYTES) {
      cryptoError('INVALID_AES_METADATA', 'Invalid AES-GCM authentication tag length');
    }
    combined = new Uint8Array(cipherBytes.length + tag.length);
    combined.set(cipherBytes, 0);
    combined.set(tag, cipherBytes.length);
  }
  if (combined.length < GCM_TAG_LENGTH_BYTES) {
    cryptoError('CORRUPTED_CIPHERTEXT', 'Ciphertext is too short to be valid AES-GCM data');
  }
  const key = await deriveAesKey(params.passphrase, salt);
  try {
    const raw = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(iv), tagLength: GCM_TAG_LENGTH_BITS },
      key,
      asBufferSource(combined),
    );
    return {
      operation: 'decrypt',
      algorithm: 'AES-256-GCM',
      plaintext: TEXT_DECODER.decode(new Uint8Array(raw)),
      reversible: true,
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === 'OperationError') {
      cryptoError('INCORRECT_PASSPHRASE', 'Decryption failed: incorrect passphrase or corrupted data');
    }
    cryptoError('UNKNOWN_CIPHER_FAILURE', 'Decryption failed unexpectedly');
  }
}

export async function hmacGenerateKey(byteLength = 32): Promise<HmacKeyMaterial> {
  if (!Number.isInteger(byteLength) || byteLength < 16) {
    cryptoError('INVALID_ARGUMENT', 'HMAC key length must be an integer of at least 16 bytes');
  }
  const keyBytes = randomBytes(byteLength);
  return {
    algorithm: 'HS256',
    keyBytes,
    keyHex: bytesToHex(keyBytes),
    keyBase64: bytesToBase64(keyBytes),
    keyLengthBits: byteLength * 8,
  };
}

function hmacKeyBytes(key: HmacKeyMaterial | Uint8Array | string, format: HmacKeyFormat): Uint8Array {
  if (typeof key === 'string') {
    if (format === 'base64') {
      return base64ToBytes(key);
    }
    if (format === 'hex') {
      return hexToBytes(key);
    }
    cryptoError('INVALID_ARGUMENT', 'String HMAC keys must be provided in base64 or hex format');
  }
  if (key instanceof Uint8Array) {
    return key;
  }
  if ('keyBytes' in key) {
    return key.keyBytes;
  }
  cryptoError('INVALID_ARGUMENT', 'Invalid HMAC key input');
}

export async function hmacImportKey(
  key: HmacKeyMaterial | Uint8Array | string,
  format: HmacKeyFormat = 'base64',
): Promise<CryptoKey> {
  assertWebCryptoSupported();
  return crypto.subtle.importKey(
    'raw',
    asBufferSource(hmacKeyBytes(key, format)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

async function hmacCryptoKey(key: HmacKeyMaterial | CryptoKey): Promise<CryptoKey> {
  if ('keyBytes' in key) {
    return hmacImportKey(key);
  }
  return key;
}

export async function hmacSign(message: string, key: HmacKeyMaterial | CryptoKey): Promise<HmacSignResult> {
  assertWebCryptoSupported();
  const cryptoKey = await hmacCryptoKey(key);
  const signature = new Uint8Array(
    await crypto.subtle.sign('HMAC', cryptoKey, asBufferSource(TEXT_ENCODER.encode(message))),
  );
  const mac = bytesToHex(signature);
  return {
    operation: 'hmac-sign',
    algorithm: 'HMAC-SHA256',
    mac,
    macLengthBits: mac.length * 4,
  };
}

export async function hmacVerify(
  message: string,
  macHex: string,
  key: HmacKeyMaterial | CryptoKey,
): Promise<HmacVerifyResult> {
  assertWebCryptoSupported();
  let signature: Uint8Array;
  try {
    signature = hexToBytes(macHex);
  } catch {
    cryptoError('INVALID_HMAC_VERIFICATION', 'HMAC signature must be valid hexadecimal');
  }
  const cryptoKey = await hmacCryptoKey(key);
  const valid = await crypto.subtle.verify(
    'HMAC',
    cryptoKey,
    asBufferSource(signature),
    asBufferSource(TEXT_ENCODER.encode(message)),
  );
  return {
    operation: 'hmac-verify',
    algorithm: 'HMAC-SHA256',
    valid,
  };
}

export const cryptoEngine = {
  isWebCryptoSupported,
  assertWebCryptoSupported,
  randomBytes,
  generateRandomBytes,
  utf8Encode,
  utf8Decode,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  utf8ToHex,
  hexToUtf8,
  utf8ToBase64,
  base64ToUtf8,
  encodeText,
  decodeText,
  hashText,
  aesEncrypt,
  aesDecrypt,
  hmacGenerateKey,
  hmacImportKey,
  hmacSign,
  hmacVerify,
  CryptoEngineError,
};

export default cryptoEngine;