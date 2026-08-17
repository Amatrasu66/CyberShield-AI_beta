export type CryptoHashAlgorithm = 'sha256' | 'sha512';

export type CryptoEncoding = 'base64' | 'hex';

export type HmacKeyFormat = 'raw' | 'hex' | 'base64';

export interface HashResult {
  readonly operation: 'hash';
  readonly algorithm: CryptoHashAlgorithm;
  readonly digest: string;
  readonly digestLengthBits: number;
  readonly inputBytes: number;
  readonly reversible: false;
}

export interface EncodingResult {
  readonly operation: 'encode' | 'decode';
  readonly encoding: CryptoEncoding;
  readonly data: string;
  readonly note: string;
}

export interface AesEncryptParams {
  readonly plaintext: string;
  readonly passphrase: string;
}

export interface AesEncryptResult {
  readonly operation: 'encrypt';
  readonly algorithm: 'AES-256-GCM';
  readonly keyDerivation: string;
  readonly authTagBits: number;
  readonly ciphertext: string;
  readonly salt: string;
  readonly iv: string;
  readonly tag: string;
  readonly reversible: true;
}

export interface AesDecryptParams {
  readonly ciphertext: string;
  readonly passphrase: string;
  readonly salt: string;
  readonly iv: string;
  readonly tag?: string;
}

export interface AesDecryptResult {
  readonly operation: 'decrypt';
  readonly algorithm: 'AES-256-GCM';
  readonly plaintext: string;
  readonly reversible: true;
}

export interface HmacKeyMaterial {
  readonly algorithm: 'HS256';
  readonly keyBytes: Uint8Array;
  readonly keyHex: string;
  readonly keyBase64: string;
  readonly keyLengthBits: number;
}

export interface HmacSignResult {
  readonly operation: 'hmac-sign';
  readonly algorithm: 'HMAC-SHA256';
  readonly mac: string;
  readonly macLengthBits: number;
}

export interface HmacVerifyResult {
  readonly operation: 'hmac-verify';
  readonly algorithm: 'HMAC-SHA256';
  readonly valid: boolean;
}

export interface RandomBytesResult {
  readonly lengthBytes: number;
  readonly bytes: Uint8Array;
  readonly hex: string;
  readonly base64: string;
}

export type CryptoEngineErrorCode =
  | 'UNSUPPORTED_BROWSER_CRYPTO'
  | 'INVALID_ARGUMENT'
  | 'INVALID_BASE64'
  | 'INVALID_HEX'
  | 'INVALID_AES_METADATA'
  | 'INCORRECT_PASSPHRASE'
  | 'CORRUPTED_CIPHERTEXT'
  | 'UNKNOWN_CIPHER_FAILURE'
  | 'INVALID_HMAC_VERIFICATION';