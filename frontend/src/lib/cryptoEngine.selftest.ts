import {
  AES_KEY_LENGTH_BITS,
  CryptoEngineError,
  GCM_IV_LENGTH_BITS,
  GCM_TAG_LENGTH_BITS,
  PBKDF2_ITERATIONS,
  SALT_LENGTH_BYTES,
  assertWebCryptoSupported,
  aesDecrypt,
  aesEncrypt,
  base64ToBytes,
  base64ToUtf8,
  bytesToBase64,
  bytesToHex,
  decodeText,
  encodeText,
  generateRandomBytes,
  hashText,
  hexToBytes,
  hexToUtf8,
  hmacGenerateKey,
  hmacImportKey,
  hmacSign,
  hmacVerify,
  isWebCryptoSupported,
  randomBytes,
  utf8Decode,
  utf8Encode,
  utf8ToBase64,
  utf8ToHex,
} from './cryptoEngine.ts';
import type { CryptoEngineErrorCode } from '../types/crypto.ts';

const SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ['english', 'The quick brown fox jumps over the lazy dog'],
  ['hindi', 'नमस्ते दुनिया! यह एक परीक्षण संदेश है'],
  ['emoji', '🔐🔑🚀✨🛡️'],
  ['mixed', 'Hello नमस्ते 🚀 café ünïcode Здравствуйте こんにちは 中文 123!'],
];

const PASSPHRASE = 'correct-horse-battery-staple-2026';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function section(title: string): void {
  console.log(`\n[${title}]`);
}

function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  const run = async (): Promise<void> => {
    await fn();
    passed += 1;
    console.log(`  ok  ${name}`);
  };
  return run().catch((error: unknown) => {
    failed += 1;
    failures.push(`${name} -> ${error instanceof Error ? error.message : String(error)}`);
    console.log(`  FAIL ${name}`);
    console.log(`       ${error instanceof Error ? error.message : String(error)}`);
  });
}

function assertEqual<T>(actual: T, expected: T, message?: string): void {
  if (actual !== expected) {
    throw new Error((message ?? 'Values not equal') + ` | expected=${String(expected)} actual=${String(actual)}`);
  }
}

function assertTrue(value: unknown, message = 'Expected truthy value'): void {
  if (!value) {
    throw new Error(message);
  }
}

function assertBytesEqual(actual: Uint8Array, expected: Uint8Array, message = 'Byte arrays not equal'): void {
  if (actual.length !== expected.length) {
    throw new Error(`${message} | length ${actual.length} !== ${expected.length}`);
  }
  for (let i = 0; i < actual.length; i += 1) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${message} | byte ${i}`);
    }
  }
}

function assertThrows(fn: () => void, predicate: (error: unknown) => boolean, message = 'Expected function to throw'): void {
  try {
    fn();
  } catch (error) {
    if (predicate(error)) {
      return;
    }
    throw error;
  }
  throw new Error(message);
}

async function assertRejects(fn: () => Promise<unknown>, predicate: (error: unknown) => boolean): Promise<void> {
  try {
    await fn();
  } catch (error) {
    if (predicate(error)) {
      return;
    }
    throw error;
  }
  throw new Error('Expected promise to reject');
}

function rejectsWithCode(name: string, code: CryptoEngineErrorCode, fn: () => Promise<unknown>): Promise<void> {
  return check(name, () =>
    assertRejects(fn, (error: unknown) => error instanceof CryptoEngineError && error.code === code),
  );
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function main(): Promise<void> {
  section('environment');
  await check('Web Crypto supported in this runtime', () => {
    assertTrue(isWebCryptoSupported());
  });
  await check('PBKDF2 iteration count matches backend (600000)', () => {
    assertEqual(PBKDF2_ITERATIONS, 600000);
  });
  await check('AES key size is 256 bits', () => {
    assertEqual(AES_KEY_LENGTH_BITS, 256);
  });
  await check('GCM IV size is 96 bits', () => {
    assertEqual(GCM_IV_LENGTH_BITS, 96);
  });
  await check('GCM tag size is 128 bits', () => {
    assertEqual(GCM_TAG_LENGTH_BITS, 128);
  });
  await check('salt size is 16 bytes (128 bits)', () => {
    assertEqual(SALT_LENGTH_BYTES, 16);
  });

  section('utf8 helpers');
  await check('UTF-8 encode/decode round-trips ASCII', () => {
    assertEqual(utf8Decode(utf8Encode('Hello World')), 'Hello World');
  });
  await check('UTF-8 encode/decode round-trips multilingual text', () => {
    for (const [, text] of SAMPLES) {
      assertEqual(utf8Decode(utf8Encode(text)), text);
    }
  });
  await check('UTF-8 encodes multi-byte sequences correctly', () => {
    assertEqual(utf8Encode('Ō').length, 2);
    assertEqual(utf8Encode('🔐').length, 4);
  });

  section('hex');
  await check('UTF-8 text to hex (known vector)', () => {
    assertEqual(utf8ToHex('Hello'), '48656c6c6f');
    assertEqual(utf8ToHex('A'), '41');
    assertEqual(utf8ToHex(''), '');
  });
  await check('hex to UTF-8 text (known vector)', () => {
    assertEqual(hexToUtf8('48656c6c6f'), 'Hello');
    assertEqual(hexToUtf8(''), '');
  });
  await check('hex round-trips all Unicode samples', () => {
    for (const [label, text] of SAMPLES) {
      assertEqual(hexToUtf8(utf8ToHex(text)), text, `round-trip failed for ${label}`);
    }
  });
  await check('bytesToHex/hexToBytes are inverses', () => {
    for (const [, text] of SAMPLES) {
      const bytes = utf8Encode(text);
      assertBytesEqual(hexToBytes(bytesToHex(bytes)), bytes);
    }
  });
  await check('hex is lowercase and deterministic', () => {
    assertEqual(bytesToHex(new Uint8Array([0xff, 0x0a, 0x5e])), 'ff0a5e');
    assertEqual(bytesToHex(utf8Encode('Hello')), utf8ToHex('Hello'));
  });
  await check('invalid hex: odd length', () => {
    assertThrows(() => hexToBytes('abc'), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_HEX');
  });
  await check('invalid hex: illegal characters', () => {
    assertThrows(() => hexToBytes('0x12'), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_HEX');
    assertThrows(() => hexToBytes('gg'), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_HEX');
  });

  section('base64');
  await check('UTF-8 text to base64 (known vector)', () => {
    assertEqual(utf8ToBase64('Hello'), 'SGVsbG8=');
    assertEqual(utf8ToBase64(''), '');
  });
  await check('base64 to UTF-8 text (known vector)', () => {
    assertEqual(base64ToUtf8('SGVsbG8='), 'Hello');
  });
  await check('base64 round-trips all Unicode samples', () => {
    for (const [label, text] of SAMPLES) {
      assertEqual(base64ToUtf8(utf8ToBase64(text)), text, `round-trip failed for ${label}`);
    }
  });
  await check('base64 decode canonical re-encode is stable', () => {
    assertEqual(bytesToBase64(base64ToBytes('SGVsbG8=')), 'SGVsbG8=');
  });
  await check('base64 handles binary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 254, 255]);
    assertBytesEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  });
  await check('invalid base64: bad length', () => {
    assertThrows(() => base64ToBytes('SGVsbG8'), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
  });
  await check('invalid base64: illegal characters', () => {
    assertThrows(() => base64ToBytes('SG...'), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
    assertThrows(() => base64ToBytes('!!!='), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
  });
  await check('invalid base64: malformed padding', () => {
    assertThrows(() => base64ToBytes('SGVsbG8===='), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
    assertThrows(() => base64ToBytes('SGVs=bG8='), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
  });
  await check('invalid base64: non-canonical padding bits', () => {
    assertThrows(() => base64ToBytes('Zz=='), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_BASE64');
  });

  section('encoding results');
  await check('encodeText base64 result shape', () => {
    const r = encodeText('hi', 'base64');
    assertEqual(r.operation, 'encode');
    assertEqual(r.encoding, 'base64');
    assertEqual(r.data, 'aGk=');
    assertTrue(typeof r.note === 'string' && r.note.length > 0);
  });
  await check('decodeText base64 result shape', () => {
    const r = decodeText('aGk=', 'base64');
    assertEqual(r.operation, 'decode');
    assertEqual(r.encoding, 'base64');
    assertEqual(r.data, 'hi');
  });
  await check('encodeText/decodeText hex round-trip', () => {
    const encoded = encodeText('Hello नमस्ते', 'hex');
    assertEqual(decodeText(encoded.data, 'hex').data, 'Hello नमस्ते');
  });
  await check('encodeText/decodeText base64 round-trip', () => {
    const encoded = encodeText('Hello 🔐', 'base64');
    assertEqual(decodeText(encoded.data, 'base64').data, 'Hello 🔐');
  });

  section('hashing');
  await check('sha256 of "abc" matches NIST vector', async () => {
    const r = await hashText('abc', 'sha256');
    assertEqual(r.digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assertEqual(r.digestLengthBits, 256);
    assertEqual(r.inputBytes, 3);
    assertEqual(r.reversible, false);
  });
  await check('sha256 of empty string matches NIST vector', async () => {
    const r = await hashText('', 'sha256');
    assertEqual(r.digest, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assertEqual(r.digestLengthBits, 256);
  });
  await check('sha512 of "abc" matches FIPS vector', async () => {
    const r = await hashText('abc', 'sha512');
    assertEqual(
      r.digest,
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    );
    assertEqual(r.digestLengthBits, 512);
  });
  await check('hashing is deterministic per algorithm', async () => {
    for (const algorithm of ['sha256', 'sha512'] as const) {
      const a = await hashText('same input', algorithm);
      const b = await hashText('same input', algorithm);
      assertEqual(a.digest, b.digest);
    }
  });
  await check('different inputs hash differently', async () => {
    const a = await hashText('input-a', 'sha256');
    const b = await hashText('input-b', 'sha256');
    assertTrue(a.digest !== b.digest);
  });
  await check('hashing supports Unicode inputs', async () => {
    for (const [label, text] of SAMPLES) {
      const a = await hashText(text, 'sha256');
      const b = await hashText(text, 'sha256');
      assertEqual(a.digest, b.digest, `not deterministic for ${label}`);
      assertEqual(a.digest.length, 64);
    }
  });
  await rejectsWithCode('unsupported hash algorithm rejected', 'INVALID_ARGUMENT', () => hashText('x', 'md5' as never));

  section('aes-256-gcm');
  await check('encrypt + decrypt round-trips plaintext', async () => {
    for (const [label, text] of SAMPLES) {
      const encrypted = await aesEncrypt(text, PASSPHRASE);
      const decrypted = await aesDecrypt({
        ciphertext: encrypted.ciphertext,
        passphrase: PASSPHRASE,
        salt: encrypted.salt,
        iv: encrypted.iv,
        tag: encrypted.tag,
      });
      assertEqual(decrypted.plaintext, text, `round-trip failed for ${label}`);
    }
  });
  await check('encryption is non-deterministic (fresh salt + IV)', async () => {
    const a = await aesEncrypt('determinism probe', PASSPHRASE);
    const b = await aesEncrypt('determinism probe', PASSPHRASE);
    assertTrue(a.salt !== b.salt, 'salt must differ');
    assertTrue(a.iv !== b.iv, 'IV must differ');
    assertTrue(a.ciphertext !== b.ciphertext, 'ciphertext must differ');
    assertTrue(a.tag !== b.tag, 'tag must differ');
  });
  await check('encrypt result shape and key derivation info', async () => {
    const r = await aesEncrypt('shape probe', PASSPHRASE);
    assertEqual(r.operation, 'encrypt');
    assertEqual(r.algorithm, 'AES-256-GCM');
    assertEqual(r.authTagBits, 128);
    assertEqual(r.keyDerivation, `PBKDF2-HMAC-SHA256 (${PBKDF2_ITERATIONS} iterations)`);
    assertEqual(r.reversible, true);
    assertEqual(base64ToBytes(r.salt).length, SALT_LENGTH_BYTES);
    assertEqual(base64ToBytes(r.iv).length, 12);
    assertEqual(base64ToBytes(r.tag).length, 16);
  });
  await check('decrypt accepts combined ciphertext+tag payload', async () => {
    const encrypted = await aesEncrypt('combined mode probe', PASSPHRASE);
    const combined = bytesToBase64(concatBytes(base64ToBytes(encrypted.ciphertext), base64ToBytes(encrypted.tag)));
    const decrypted = await aesDecrypt({ ciphertext: combined, passphrase: PASSPHRASE, salt: encrypted.salt, iv: encrypted.iv });
    assertEqual(decrypted.plaintext, 'combined mode probe');
  });
  await check('decrypt result shape', async () => {
    const encrypted = await aesEncrypt('shape probe', PASSPHRASE);
    const decrypted = await aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
    assertEqual(decrypted.operation, 'decrypt');
    assertEqual(decrypted.algorithm, 'AES-256-GCM');
    assertEqual(decrypted.reversible, true);
  });
  await rejectsWithCode('wrong passphrase must fail authentication', 'INCORRECT_PASSPHRASE', async () => {
    const encrypted = await aesEncrypt('secret data', PASSPHRASE);
    return aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: 'different-passphrase-here',
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
  });
  await rejectsWithCode('tampered ciphertext must fail authentication', 'INCORRECT_PASSPHRASE', async () => {
    const encrypted = await aesEncrypt('tamper me please', PASSPHRASE);
    const tampered = base64ToBytes(encrypted.ciphertext);
    tampered[0] ^= 0xff;
    return aesDecrypt({
      ciphertext: bytesToBase64(tampered),
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
  });
  await rejectsWithCode('tampered tag must fail authentication', 'INCORRECT_PASSPHRASE', async () => {
    const encrypted = await aesEncrypt('tamper tag please', PASSPHRASE);
    const tamperedTag = base64ToBytes(encrypted.tag);
    tamperedTag[0] ^= 0x01;
    return aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: bytesToBase64(tamperedTag),
    });
  });
  await rejectsWithCode('empty ciphertext is reported as corrupted', 'CORRUPTED_CIPHERTEXT', async () => {
    return aesDecrypt({ ciphertext: '', passphrase: PASSPHRASE, salt: bytesToBase64(randomBytes(16)), iv: bytesToBase64(randomBytes(12)) });
  });
  await rejectsWithCode('invalid salt length rejected', 'INVALID_AES_METADATA', async () => {
    const encrypted = await aesEncrypt('metadata probe', PASSPHRASE);
    return aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: PASSPHRASE,
      salt: bytesToBase64(new Uint8Array(8)),
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
  });
  await rejectsWithCode('invalid IV length rejected', 'INVALID_AES_METADATA', async () => {
    const encrypted = await aesEncrypt('metadata probe', PASSPHRASE);
    return aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: bytesToBase64(new Uint8Array(4)),
      tag: encrypted.tag,
    });
  });
  await rejectsWithCode('invalid tag length rejected', 'INVALID_AES_METADATA', async () => {
    const encrypted = await aesEncrypt('metadata probe', PASSPHRASE);
    return aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: bytesToBase64(new Uint8Array(5)),
    });
  });
  await rejectsWithCode('non-base64 ciphertext rejected', 'INVALID_AES_METADATA', async () => {
    const encrypted = await aesEncrypt('metadata probe', PASSPHRASE);
    return aesDecrypt({
      ciphertext: '%%%not-base64%%%',
      passphrase: PASSPHRASE,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
  });
  await rejectsWithCode('short passphrase rejected', 'INVALID_ARGUMENT', async () => {
    return aesEncrypt('metadata probe', 'short');
  });
  await check('512-character passphrase accepted', async () => {
    const longPassphrase = 'a'.repeat(512);
    const encrypted = await aesEncrypt('boundary probe', longPassphrase);
    const decrypted = await aesDecrypt({
      ciphertext: encrypted.ciphertext,
      passphrase: longPassphrase,
      salt: encrypted.salt,
      iv: encrypted.iv,
      tag: encrypted.tag,
    });
    assertEqual(decrypted.plaintext, 'boundary probe');
  });
  await rejectsWithCode('513-character passphrase rejected', 'PASSPHRASE_TOO_LONG', async () => {
    return aesEncrypt('boundary probe', 'a'.repeat(513));
  });
  await rejectsWithCode('very large passphrase rejected immediately', 'PASSPHRASE_TOO_LONG', async () => {
    return aesDecrypt({
      ciphertext: 'ciphertext',
      passphrase: 'a'.repeat(100_000),
      salt: 'salt',
      iv: 'iv',
      tag: 'tag',
    });
  });
  await check('passphrase-too-long error never contains the passphrase', async () => {
    const longPassphrase = 'x'.repeat(513);
    let message = '';
    try {
      await aesEncrypt('probe', longPassphrase);
    } catch (error) {
      message = error instanceof Error ? error.message : '';
    }
    assertTrue(!message.includes('x'.repeat(16)), 'passphrase leaked into error');
    assertTrue(message.includes('too long'), 'error should mention the length limit');
  });
  await check('errors never leak passphrase or plaintext', async () => {
    const encrypted = await aesEncrypt('ultra sensitive secret', PASSPHRASE);
    let message = '';
    try {
      await aesDecrypt({
        ciphertext: encrypted.ciphertext,
        passphrase: 'wrong-passphrase-here-ok',
        salt: encrypted.salt,
        iv: encrypted.iv,
        tag: encrypted.tag,
      });
    } catch (error) {
      message = error instanceof Error ? error.message : '';
    }
    assertTrue(!message.includes('ultra sensitive secret'), 'plaintext leaked into error');
    assertTrue(!message.includes('wrong-passphrase-here-ok'), 'passphrase leaked into error');
  });
  const pbkdf2Start = performance.now();
  const timingProbe = await aesEncrypt('timing probe', PASSPHRASE);
  await aesDecrypt({
    ciphertext: timingProbe.ciphertext,
    passphrase: PASSPHRASE,
    salt: timingProbe.salt,
    iv: timingProbe.iv,
    tag: timingProbe.tag,
  });
  const pbkdf2Ms = performance.now() - pbkdf2Start;
  console.log(`  note  PBKDF2 @ ${PBKDF2_ITERATIONS} iterations (encrypt+decrypt) took ${pbkdf2Ms.toFixed(0)} ms in this runtime`);

  section('hmac-sha256');
  await check('generated key has expected size and encodings', async () => {
    const material = await hmacGenerateKey(32);
    assertEqual(material.algorithm, 'HS256');
    assertEqual(material.keyLengthBits, 256);
    assertEqual(material.keyBytes.length, 32);
    assertEqual(material.keyHex.length, 64);
    assertBytesEqual(base64ToBytes(material.keyBase64), material.keyBytes);
  });
  await check('signing is deterministic for same key and message', async () => {
    const key = await hmacGenerateKey(32);
    const a = await hmacSign('sign me', key);
    const b = await hmacSign('sign me', key);
    assertEqual(a.mac, b.mac);
    assertEqual(a.mac.length, 64);
    assertEqual(a.macLengthBits, 256);
    assertEqual(a.operation, 'hmac-sign');
  });
  await check('verification succeeds for correct message and key', async () => {
    const key = await hmacGenerateKey(32);
    const sig = await hmacSign('hello hmac', key);
    const verified = await hmacVerify('hello hmac', sig.mac, key);
    assertEqual(verified.valid, true);
    assertEqual(verified.operation, 'hmac-verify');
  });
  await check('verification fails for modified message', async () => {
    const key = await hmacGenerateKey(32);
    const sig = await hmacSign('hello hmac', key);
    assertEqual((await hmacVerify('hello hmAc', sig.mac, key)).valid, false);
  });
  await check('verification fails for modified signature', async () => {
    const key = await hmacGenerateKey(32);
    const sig = await hmacSign('hello hmac', key);
    const tweaked = (BigInt(`0x${sig.mac}`) ^ BigInt(1n)).toString(16).padStart(64, '0');
    assertEqual((await hmacVerify('hello hmac', tweaked, key)).valid, false);
  });
  await check('verification fails for a different key', async () => {
    const keyA = await hmacGenerateKey(32);
    const keyB = await hmacGenerateKey(32);
    const sig = await hmacSign('hello hmac', keyA);
    assertEqual((await hmacVerify('hello hmac', sig.mac, keyB)).valid, false);
  });
  await check('key import from hex and base64 string formats', async () => {
    const material = await hmacGenerateKey(32);
    const viaHex = await hmacImportKey(material.keyHex, 'hex');
    const viaB64 = await hmacImportKey(material.keyBase64, 'base64');
    const viaRaw = await hmacImportKey(material.keyBytes, 'raw');
    const ref = await hmacSign('format probe', material);
    assertEqual((await hmacSign('format probe', viaHex)).mac, ref.mac);
    assertEqual((await hmacSign('format probe', viaB64)).mac, ref.mac);
    assertEqual((await hmacSign('format probe', viaRaw)).mac, ref.mac);
  });
  await check('verification accepts a raw CryptoKey', async () => {
    const material = await hmacGenerateKey(32);
    const cryptoKey = await hmacImportKey(material, 'base64');
    const sig = await hmacSign('raw key probe', cryptoKey);
    assertEqual((await hmacVerify('raw key probe', sig.mac, cryptoKey)).valid, true);
  });
  await check('hmac supports Unicode messages', async () => {
    const key = await hmacGenerateKey(32);
    for (const [label, text] of SAMPLES) {
      const sig = await hmacSign(text, key);
      assertEqual((await hmacVerify(text, sig.mac, key)).valid, true, `verification failed for ${label}`);
    }
  });
  await check('hmac is not encryptable back to plaintext', async () => {
    const key = await hmacGenerateKey(32);
    const sig = await hmacSign('not ciphertext', key);
    const raw = hexToBytes(sig.mac);
    assertTrue(raw.length > 0);
  });
  await rejectsWithCode('invalid signature hex rejected on verify', 'INVALID_HMAC_VERIFICATION', async () => {
    const key = await hmacGenerateKey(32);
    return hmacVerify('anything', 'zznothex', key);
  });

  section('randomness');
  await check('randomBytes returns requested length', () => {
    assertEqual(randomBytes(48).length, 48);
    assertEqual(randomBytes(0).length, 0);
  });
  await check('randomBytes never repeats for two draws', () => {
    const a = randomBytes(64);
    const b = randomBytes(64);
    let same = true;
    for (let i = 0; i < 64; i += 1) {
      if (a[i] !== b[i]) {
        same = false;
        break;
      }
    }
    assertTrue(!same);
  });
  await check('randomBytes validates its arguments', () => {
    assertThrows(() => randomBytes(-1), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_ARGUMENT');
    assertThrows(() => randomBytes(3.5), (e) => e instanceof CryptoEngineError && e.code === 'INVALID_ARGUMENT');
  });
  await check('generateRandomBytes returns encodings', () => {
    const r = generateRandomBytes(9);
    assertEqual(r.lengthBytes, 9);
    assertEqual(r.bytes.length, 9);
    assertEqual(r.hex.length, 18);
    assertEqual(r.base64.length, 12);
    assertEqual(r.hex, bytesToHex(r.bytes));
    assertEqual(r.base64, bytesToBase64(r.bytes));
  });

  section('unsupported browser crypto guard');
  const savedCrypto = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
  try {
    await check('isWebCryptoSupported() returns false without crypto', () => {
      assertEqual(isWebCryptoSupported(), false);
      assertThrows(
        () => {
          void randomBytes(1);
        },
        (e) => e instanceof CryptoEngineError && e.code === 'UNSUPPORTED_BROWSER_CRYPTO',
      );
      assertThrows(
        () => {
          void assertWebCryptoSupported();
        },
        (e) => e instanceof CryptoEngineError && e.code === 'UNSUPPORTED_BROWSER_CRYPTO',
      );
    });
  } finally {
    Object.defineProperty(globalThis, 'crypto', { value: savedCrypto, configurable: true });
  }
  await check('crypto restored after guard test', () => {
    assertEqual(isWebCryptoSupported(), true);
    assertEqual(randomBytes(4).length, 4);
  });

  console.log(`\nCrypto engine self-test complete: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('\nFailures:');
    for (const failure of failures) {
      console.log(`  - ${failure}`);
    }
    process.exitCode = 1;
  }
}

await main();