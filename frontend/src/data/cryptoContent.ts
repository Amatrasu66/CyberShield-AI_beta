import type { LucideIcon } from 'lucide-react';
import { Binary, Dices, Fingerprint, KeyRound, LockKeyhole } from 'lucide-react';

export type CryptoModuleId = 'hashing' | 'encoding' | 'aes' | 'hmac' | 'random';

export interface CryptoModuleInfo {
  readonly id: CryptoModuleId;
  readonly label: string;
  readonly short: string;
  readonly icon: LucideIcon;
  readonly teaches: readonly string[];
}

export interface ConceptItem {
  readonly title: string;
  readonly body: string;
}

export const cryptoModules: readonly CryptoModuleInfo[] = [
  {
    id: 'hashing',
    label: 'Hashing',
    short: 'One-way fingerprints for integrity checks',
    icon: Fingerprint,
    teaches: [
      'Hash any message with SHA-256 or SHA-512 directly in the browser.',
      'Inspect the fixed-size digest and its length in bits.',
      'Compare two inputs to observe the avalanche effect.',
      'Understand why hashes are irreversible and never a form of encryption.',
    ],
  },
  {
    id: 'encoding',
    label: 'Encoding',
    short: 'Reversible text representations — encoding is not encryption',
    icon: Binary,
    teaches: [
      'Encode and decode between text and Base64 or hex.',
      'Follow the Input → Encoded → Decoded chain.',
      'Verify that encoding needs no key and is fully reversible.',
      'Learn that encoded data carries zero confidentiality.',
    ],
  },
  {
    id: 'aes',
    label: 'AES-256-GCM',
    short: 'Authenticated symmetric encryption with PBKDF2 key derivation',
    icon: LockKeyhole,
    teaches: [
      'Encrypt a message with a passphrase entirely in the browser.',
      'Generate a fresh salt and nonce on every encryption.',
      'Reuse the ciphertext, salt, nonce and tag to decrypt in this session.',
      'Watch wrong passphrases and tampered ciphertext fail closed.',
    ],
  },
  {
    id: 'hmac',
    label: 'HMAC-SHA256',
    short: 'Keyed message authentication for integrity and authenticity',
    icon: KeyRound,
    teaches: [
      'Generate a random 256-bit shared secret.',
      'Compute an HMAC-SHA256 tag for any message.',
      'Verify the tag, then tamper with the message to see verification fail.',
      'Understand that HMAC authenticates but never encrypts.',
    ],
  },
  {
    id: 'random',
    label: 'Secure randomness',
    short: 'Cryptographically secure random bytes from the platform CSPRNG',
    icon: Dices,
    teaches: [
      'Draw random bytes in a size you choose.',
      'Inspect the hex and Base64 representations.',
      'Learn why Math.random() must never secure anything.',
      'See where salts, nonces and keys come from.',
    ],
  },
];

export const cryptoConcepts: Readonly<Record<CryptoModuleId, readonly ConceptItem[]>> = {
  hashing: [
    {
      title: 'What it does',
      body: 'A hash maps an input of any size to a fixed-size output called the digest. Hashing is a one-way function: computing the digest is fast, but recovering the original input from the digest is infeasible.',
    },
    {
      title: 'What input it accepts',
      body: 'Any text, including Unicode and even the empty string. Hashing operates on bytes, so the exact text encoding matters — "café" hashed as UTF-8 is not the same as a different byte layout.',
    },
    {
      title: 'What output it produces',
      body: 'A fixed-length hexadecimal digest regardless of input length: 256 bits for SHA-256 and 512 bits for SHA-512. A one-character message and a multi-gigabyte file both yield the same output size.',
    },
    {
      title: 'What security property it provides',
      body: 'Determinism (same input always yields the same digest) and the avalanche effect (changing a single input bit flips about half of the digest bits). Modern algorithms also provide preimage and collision resistance.',
    },
    {
      title: 'What it does NOT provide',
      body: 'Confidentiality. Hashing is not encryption: there is no key and no way to "decrypt" a digest back to the message. Anyone can compute the digest of a guessed input and compare.',
    },
    {
      title: 'When it should be used',
      body: 'Integrity verification (detecting accidental or malicious changes), confirming downloaded files, and — combined with a salt and a slow derivation function like PBKDF2 — storing password digests.',
    },
    {
      title: 'Common mistakes',
      body: 'Using MD5 or SHA-1 for security (both have practical collision attacks), relying on a fast unsalted hash for passwords (rainbow tables), and treating a digest as if it were encrypted data.',
    },
  ],
  encoding: [
    {
      title: 'What it does',
      body: 'Encoding turns bytes into a textual representation so binary data can travel through text-only channels such as email, JSON, or CSV. Base64 and hex are two common encodings.',
    },
    {
      title: 'What input and output it accepts',
      body: 'Any text or bytes in; a text-safe string out. Base64 output uses the A–Z, a–z, 0–9, +, / alphabet with = padding. Hex output uses only 0–9 and a–f, with two characters per byte.',
    },
    {
      title: 'Reversible without any secret',
      body: 'Encoding is always fully reversible: anyone can decode the result without a key because there is no secret involved. The transformation is purely presentational.',
    },
    {
      title: 'Encoding is NOT encryption',
      body: 'Base64 and hex provide zero confidentiality. Base64 of "secret" is "c2VjcmV0" — trivially readable. Malware and phishing kits often hide payloads in Base64, but that adds only a layer of appearance, not security.',
    },
    {
      title: 'When it should be used',
      body: 'Embedding binary data in JSON, CSV or email; representing keys, salts, nonces and digests as text; and safe transport in contexts that only accept printable characters.',
    },
    {
      title: 'Common mistakes',
      body: 'Treating Base64/hex as encryption, relying on them to hide secrets, mixing hex and Base64 formats, and ignoring padding or alphabet rules when decoding.',
    },
  ],
  aes: [
    {
      title: 'What it does',
      body: 'AES-256-GCM is symmetric authenticated encryption: it provides confidentiality and integrity/authenticity together. The same key material encrypts and decrypts, so the secret must be shared securely with the recipient.',
    },
    {
      title: 'The passphrase is not the key',
      body: 'AES needs a 256-bit key, but your passphrase is not that key. PBKDF2-HMAC-SHA256 with 600,000 iterations stretches the passphrase into a 256-bit AES key, mixing in a random salt so different runs derive different material.',
    },
    {
      title: 'Salt',
      body: 'A random 16-byte value fed into key derivation. It makes derivation non-deterministic (the same passphrase yields different effective keys per run) and defeats precomputed rainbow tables.',
    },
    {
      title: 'Nonce / IV',
      body: 'A 96-bit random value that must be unique for every message encrypted under the same key. Reusing a nonce with the same key can let an attacker recover plaintext and forge data. Every encryption here draws a fresh nonce.',
    },
    {
      title: 'Authentication tag',
      body: 'GCM appends a 128-bit tag that cryptographically binds the ciphertext to the key and nonce. Altering any bit of the ciphertext — or using the wrong passphrase — makes the tag check fail, so decryption refuses to return fabricated results.',
    },
    {
      title: 'Why decryption needs the whole payload',
      body: 'Reversibility only works when the correct ingredients are available: passphrase, salt, nonce, ciphertext and tag. Wrong passphrase or corrupted ciphertext causes a hard failure instead of silently producing garbage.',
    },
    {
      title: 'What it does NOT do',
      body: 'It does not hide the message length, it cannot rescue low-entropy passphrases from offline brute force in ideal conditions (the 600,000-iteration KDF only slows attackers down), and it does not protect the machine running it.',
    },
  ],
  hmac: [
    {
      title: 'What it does',
      body: 'HMAC is a keyed message-authentication code: it produces a fixed-size tag that proves a message came from someone who holds the shared secret and that the message was not altered in transit.',
    },
    {
      title: 'What input it accepts',
      body: 'A message (any text) and a secret key. Here the engine uses HMAC-SHA256 and produces a 256-bit tag rendered as 64 hexadecimal characters.',
    },
    {
      title: 'Integrity and authenticity',
      body: 'Changing anything — the message or the key — changes the tag. Only parties who know the same secret can produce a tag that verifies. The Web Crypto verify operation performs a constant-time comparison, avoiding timing leaks.',
    },
    {
      title: 'HMAC is NOT encryption',
      body: 'HMAC does not hide the message. The message stays fully readable: the tag is a secret-salted checksum, not ciphertext. It proves who could have written the message, not its secrecy.',
    },
    {
      title: 'When it should be used',
      body: 'Signing API requests, authenticating tokens such as HS256 JWTs, and verifying message integrity across channels where both parties share a secret.',
    },
    {
      title: 'Common mistakes',
      body: 'Using HMAC as if it encrypted data, choosing weak or reused keys, deriving tags over unclear message boundaries, and comparing tags in a non-constant-time way.',
    },
  ],
  random: [
    {
      title: 'What it is',
      body: 'Cryptographically secure randomness: bytes drawn from the platform CSPRNG via crypto.getRandomValues(). The output is statistically random and unpredictable to any attacker without the entropy source.',
    },
    {
      title: 'Why Math.random() is not enough',
      body: 'Math.random() is optimized for speed and game logic, is typically deterministic and seedable, and carries no guarantee of cryptographic strength. Using it to generate keys, tokens or salts is unsafe.',
    },
    {
      title: 'Where randomness is used in cryptography',
      body: 'Salts (16 bytes in this lab’s AES), GCM nonces (12 bytes), AES keys (32 bytes), HMAC keys, session tokens and UUIDs. Every place a value must be secret and unpredictable needs a CSPRNG.',
    },
    {
      title: 'What output it produces',
      body: 'A requested number of bytes as a Uint8Array, with precomputed hex and Base64 views. A 32-byte draw yields up to 256 bits of entropy when drawn from a uniform CSPRNG.',
    },
    {
      title: 'Random bytes are not user-friendly credentials',
      body: 'Random bytes make excellent keys and tokens, but they are poor passwords. Use them as cryptographic material, and use passphrases or a password manager for things people must remember.',
    },
    {
      title: 'Common mistakes',
      body: 'Reusing salts or nonces, seeding custom RNGs with time(), or trusting Math.random() or Date.now() as a source of secrets.',
    },
  ],
};