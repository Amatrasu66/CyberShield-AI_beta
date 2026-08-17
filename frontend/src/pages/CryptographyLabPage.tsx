import { useState, type FormEvent, type ReactNode } from 'react';
import {
  AlertCircle,
  ArrowRight,
  Check,
  CheckCircle,
  Copy,
  Eye,
  EyeOff,
  Info,
  Layers,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { cryptoConcepts, cryptoModules, type CryptoModuleId } from '../data/cryptoContent';
import {
  AES_KEY_DERIVATION,
  CryptoEngineError,
  aesDecrypt,
  aesEncrypt,
  decodeText,
  encodeText,
  generateRandomBytes,
  hashText,
  hmacGenerateKey,
  hmacImportKey,
  hmacSign,
  hmacVerify,
  isWebCryptoSupported,
} from '../lib/cryptoEngine';
import type {
  AesEncryptResult,
  CryptoEncoding,
  CryptoHashAlgorithm,
  HashResult,
  HmacKeyFormat,
  HmacKeyMaterial,
  HmacSignResult,
  HmacVerifyResult,
  RandomBytesResult,
} from '../types/crypto';
import { cn } from '../utils/cn';

const INPUT_CLASS =
  'h-11 rounded border bg-surface-low px-3 font-mono text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:opacity-60';
const TEXTAREA_CLASS =
  'rounded border bg-surface-low p-3 font-mono text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:opacity-60';
const SELECT_CLASS =
  'h-11 rounded border bg-surface px-3 text-sm text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:opacity-60';

function friendlyCryptoError(error: unknown): string {
  if (error instanceof CryptoEngineError) {
    return error.message;
  }
  return 'The operation failed unexpectedly. Please try again.';
}

interface FieldProps {
  readonly id: string;
  readonly label: string;
  readonly hint?: string;
  readonly children: ReactNode;
}

function Field({ id, label, hint, children }: FieldProps) {
  return (
    <div className="grid gap-2 text-sm font-medium text-on-surface">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint !== undefined && <p className="text-xs leading-5 text-on-surface-variant">{hint}</p>}
    </div>
  );
}

function ErrorAlert({ message }: { readonly message: string }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded border border-danger/30 bg-danger/5 p-3 text-sm text-danger">
      <AlertCircle size={16} className="mt-0.5 shrink-0" />
      <p>{message}</p>
    </div>
  );
}

function MetricTile({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div className="rounded border bg-surface-low p-3">
      <p className="eyebrow mb-1">{label}</p>
      <p className="break-words font-mono text-sm text-on-surface">{value}</p>
    </div>
  );
}

interface CodeBlockProps {
  readonly label: string;
  readonly value: string;
  readonly copyable?: boolean;
}

function CodeBlock({ label, value, copyable = true }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be blocked; the operation is not critical.
    }
  };
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <p className="eyebrow">{label}</p>
        {copyable && value !== '' && (
          <button
            type="button"
            onClick={() => void handleCopy()}
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60"
            aria-label={`Copy ${label}`}
          >
            {copied ? (
              <>
                <Check size={12} className="text-success" /> Copied
              </>
            ) : (
              <>
                <Copy size={12} /> Copy
              </>
            )}
          </button>
        )}
      </div>
      <pre className="break-all whitespace-pre-wrap rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">
        {value === '' ? '—' : value}
      </pre>
    </div>
  );
}

function ConceptItem({ title, body }: { readonly title: string; readonly body: string }) {
  return (
    <div className="py-3 first:pt-0 last:pb-0">
      <p className="text-sm font-semibold text-on-surface">{title}</p>
      <p className="mt-1 text-sm leading-6 text-on-surface-variant">{body}</p>
    </div>
  );
}

interface PassphraseInputProps {
  readonly id: string;
  readonly value: string;
  readonly visible: boolean;
  readonly disabled: boolean;
  readonly onChange: (value: string) => void;
  readonly onToggle: () => void;
}

function PassphraseInput({ id, value, visible, disabled, onChange, onToggle }: PassphraseInputProps) {
  return (
    <div className="relative">
      <input
        id={id}
        type={visible ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        autoComplete="new-password"
        className={cn(INPUT_CLASS, 'w-full pr-11')}
      />
      <button
        type="button"
        onClick={onToggle}
        disabled={disabled}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60"
        aria-label={visible ? 'Hide passphrase' : 'Show passphrase'}
      >
        {visible ? <EyeOff size={18} /> : <Eye size={18} />}
      </button>
    </div>
  );
}

function HashingModule() {
  const [algorithm, setAlgorithm] = useState<CryptoHashAlgorithm>('sha256');
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<HashResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [compareInput, setCompareInput] = useState('');
  const [compareOther, setCompareOther] = useState('');
  const [compareBusy, setCompareBusy] = useState(false);
  const [comparison, setComparison] = useState<{ readonly same: boolean; readonly left: string; readonly right: string } | null>(null);
  const [compareError, setCompareError] = useState<string | null>(null);

  const handleAlgorithmChange = (value: string) => {
    setAlgorithm(value as CryptoHashAlgorithm);
    setResult(null);
    setComparison(null);
    setError(null);
    setCompareError(null);
  };

  const handleInputChange = (value: string) => {
    setInput(value);
    setError(null);
    setResult(null);
  };

  const handleGenerate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (busy) return;
    if (input === '') {
      setError('Enter a message to hash.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const hash = await hashText(input, algorithm);
      setResult(hash);
    } catch (err) {
      setError(friendlyCryptoError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleReset = () => {
    setInput('');
    setResult(null);
    setError(null);
    setCompareInput('');
    setCompareOther('');
    setComparison(null);
    setCompareError(null);
  };

  const handleCompare = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (compareBusy) return;
    if (compareInput === '' || compareOther === '') {
      setCompareError('Enter a value for both inputs to compare.');
      return;
    }
    setCompareBusy(true);
    setCompareError(null);
    setComparison(null);
    try {
      const left = await hashText(compareInput, algorithm);
      const right = await hashText(compareOther, algorithm);
      setComparison({ same: left.digest === right.digest, left: left.digest, right: right.digest });
    } catch (err) {
      setCompareError(friendlyCryptoError(err));
    } finally {
      setCompareBusy(false);
    }
  };

  return (
    <>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Compute a message digest</p>
          <form onSubmit={handleGenerate} className="mt-6 grid gap-4" aria-busy={busy}>
            <Field id="hash-algorithm" label="Hash algorithm">
              <select
                id="hash-algorithm"
                value={algorithm}
                onChange={(e) => handleAlgorithmChange(e.target.value)}
                disabled={busy}
                className={SELECT_CLASS}
              >
                <option value="sha256">SHA-256 · 256-bit digest</option>
                <option value="sha512">SHA-512 · 512-bit digest</option>
              </select>
            </Field>
            <Field id="hash-input" label="Message to hash">
              <textarea
                id="hash-input"
                rows={4}
                value={input}
                onChange={(e) => handleInputChange(e.target.value)}
                disabled={busy}
                maxLength={10000}
                placeholder="Type or paste any message, including Unicode"
                aria-describedby="hash-hint"
                className={cn(TEXTAREA_CLASS, 'resize-none')}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={busy}>
                {busy ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Hashing…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Generate digest
                  </>
                )}
              </Button>
              <Button type="button" variant="secondary" onClick={handleReset} disabled={busy}>
                <RotateCcw size={16} /> Reset
              </Button>
            </div>
            <p id="hash-hint" className="text-xs leading-5 text-on-surface-variant">
              Hashing runs locally via the Web Crypto API. The same message always produces the same digest; changing a single character produces a completely different one.
            </p>
            {error !== null && <ErrorAlert message={error} />}
          </form>
        </Card>

        <Card className="p-5">
          {result !== null ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Message digest</p>
                  <p className="mt-2 font-display text-xl font-bold text-on-surface">
                    {result.algorithm === 'sha256' ? 'SHA-256' : 'SHA-512'}
                  </p>
                </div>
                <Badge tone="primary">
                  <CheckCircle size={12} className="mr-1" /> One-way
                </Badge>
              </div>
              <div className="mt-6 grid gap-3 sm:grid-cols-3">
                <MetricTile label="Digest length" value={`${result.digestLengthBits} bits`} />
                <MetricTile label="Input size" value={`${result.inputBytes} bytes`} />
                <MetricTile label="Reversible" value="No" />
              </div>
              <div className="mt-5">
                <CodeBlock label="Hex digest" value={result.digest} />
              </div>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Message digest</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Output</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  Enter a message and generate the digest to see a fixed-size hexadecimal fingerprint.
                </p>
              </div>
            </>
          )}
        </Card>
      </div>

      <Card className="mt-5">
        <div className="border-b px-5 py-4">
          <p className="font-display font-semibold flex items-center gap-2">
            <ArrowRight size={18} className="text-primary" /> Avalanche effect — compare two messages
          </p>
        </div>
        <div className="p-5">
          <form onSubmit={handleCompare} className="grid gap-4 lg:grid-cols-[1fr_1fr_auto]" aria-busy={compareBusy}>
            <Field id="hash-compare-a" label="Message A">
              <input
                id="hash-compare-a"
                type="text"
                value={compareInput}
                onChange={(e) => {
                  setCompareInput(e.target.value);
                  setCompareError(null);
                }}
                disabled={compareBusy}
                placeholder="e.g. hello"
                className={INPUT_CLASS}
              />
            </Field>
            <Field id="hash-compare-b" label="Message B">
              <input
                id="hash-compare-b"
                type="text"
                value={compareOther}
                onChange={(e) => {
                  setCompareOther(e.target.value);
                  setCompareError(null);
                }}
                disabled={compareBusy}
                placeholder="e.g. Hello"
                className={INPUT_CLASS}
              />
            </Field>
            <div className="flex items-end">
              <Button type="submit" disabled={compareBusy || busy}>
                {compareBusy ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Hashing…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Compare
                  </>
                )}
              </Button>
            </div>
          </form>
          {compareError !== null && <div className="mt-4"><ErrorAlert message={compareError} /></div>}
          {comparison !== null && (
            <div className="mt-5">
              <div className="flex items-center gap-2">
                {comparison.same ? (
                  <Badge tone="success">
                    <CheckCircle size={12} className="mr-1" /> Identical digests — same input, same hash
                  </Badge>
                ) : (
                  <Badge tone="warning">
                    <AlertCircle size={12} className="mr-1" /> Different digests — avalanche effect
                  </Badge>
                )}
              </div>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <CodeBlock label="Digest A" value={comparison.left} />
                <CodeBlock label="Digest B" value={comparison.right} />
              </div>
              {!comparison.same && (
                <p className="mt-3 text-xs leading-5 text-on-surface-variant">
                  A single-character change flips roughly half of the digest bits. This is the avalanche effect, and it is why hashes expose even tiny alterations.
                </p>
              )}
            </div>
          )}
        </div>
      </Card>
    </>
  );
}

function EncodingModule() {
  const [encoding, setEncoding] = useState<CryptoEncoding>('base64');
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [input, setInput] = useState('');
  const [original, setOriginal] = useState<string | null>(null);
  const [encoded, setEncoded] = useState<string | null>(null);
  const [decoded, setDecoded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleInputChange = (value: string) => {
    setInput(value);
    setError(null);
    setOriginal(null);
    setEncoded(null);
    setDecoded(null);
  };

  const handleModeChange = (next: 'encode' | 'decode') => {
    setMode(next);
    setError(null);
  };

  const handleRun = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (input === '') {
      setError('Enter some text to encode or decode.');
      return;
    }
    try {
      if (mode === 'encode') {
        const enc = encodeText(input, encoding);
        const dec = decodeText(enc.data, encoding);
        setOriginal(input);
        setEncoded(enc.data);
        setDecoded(dec.data);
      } else {
        const dec = decodeText(input, encoding);
        setOriginal(input);
        setEncoded(input);
        setDecoded(dec.data);
      }
      setError(null);
    } catch (err) {
      setOriginal(null);
      setEncoded(null);
      setDecoded(null);
      setError(friendlyCryptoError(err));
    }
  };

  const handleReset = () => {
    setInput('');
    setOriginal(null);
    setEncoded(null);
    setDecoded(null);
    setError(null);
  };

  const encodingLabel = encoding === 'base64' ? 'Base64' : 'Hex';

  return (
    <>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Convert text</p>
          <form onSubmit={handleRun} className="mt-6 grid gap-4">
            <div className="grid gap-2 text-sm font-medium text-on-surface">
              <span>Encoding</span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setEncoding('base64')}
                  aria-pressed={encoding === 'base64'}
                  className={cn(
                    'h-11 rounded border px-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60',
                    encoding === 'base64'
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
                  )}
                >
                  Base64
                </button>
                <button
                  type="button"
                  onClick={() => setEncoding('hex')}
                  aria-pressed={encoding === 'hex'}
                  className={cn(
                    'h-11 rounded border px-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60',
                    encoding === 'hex'
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
                  )}
                >
                  Hex
                </button>
              </div>
            </div>
            <div className="grid gap-2 text-sm font-medium text-on-surface">
              <span>Direction</span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handleModeChange('encode')}
                  aria-pressed={mode === 'encode'}
                  className={cn(
                    'h-11 rounded border px-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60',
                    mode === 'encode'
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
                  )}
                >
                  Encode
                </button>
                <button
                  type="button"
                  onClick={() => handleModeChange('decode')}
                  aria-pressed={mode === 'decode'}
                  className={cn(
                    'h-11 rounded border px-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60',
                    mode === 'decode'
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
                  )}
                >
                  Decode
                </button>
              </div>
            </div>
            <Field
              id="encoding-input"
              label={mode === 'encode' ? 'Text to encode' : `${encodingLabel} to decode`}
            >
              <textarea
                id="encoding-input"
                rows={4}
                value={input}
                onChange={(e) => handleInputChange(e.target.value)}
                maxLength={10000}
                placeholder={mode === 'encode' ? 'Type or paste any text, including Unicode' : `Paste ${encodingLabel} data, e.g. ${encoding === 'base64' ? 'SGVsbG8=' : '48656c6c6f'}`}
                className={cn(TEXTAREA_CLASS, 'resize-none')}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit">
                <Play size={16} />
                {mode === 'encode' ? 'Encode' : 'Decode'}
              </Button>
              <Button type="button" variant="secondary" onClick={handleReset}>
                <RotateCcw size={16} /> Reset
              </Button>
            </div>
            {error !== null && <ErrorAlert message={error} />}
          </form>
        </Card>

        <Card className="p-5">
          {encoded !== null && decoded !== null ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Result</p>
                  <p className="mt-2 font-display text-lg font-bold text-on-surface">
                    {mode === 'encode' ? `${encodingLabel} encoding` : 'Decoded text'}
                  </p>
                </div>
                <Badge tone={mode === 'encode' ? 'warning' : 'success'}>
                  <Info size={12} className="mr-1" /> Not encryption
                </Badge>
              </div>
              <div className="mt-6">
                <CodeBlock label={mode === 'encode' ? `Encoded (${encodingLabel})` : `Input (as ${encodingLabel})`} value={encoded} />
              </div>
              {mode === 'encode' && (
                <div className="mt-4">
                  <CodeBlock label="Decoded back" value={decoded} />
                </div>
              )}
              <p className="mt-4 text-xs leading-5 text-on-surface-variant">
                Encoding is fully reversible without any key — decoding reveals the original bytes. It provides no secrecy.
              </p>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Encoded result</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Output</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  Encode or decode a message to see the {encodingLabel} chain.
                </p>
              </div>
            </>
          )}
        </Card>
      </div>

      <Card className="mt-5">
        <div className="border-b px-5 py-4">
          <p className="font-display font-semibold flex items-center gap-2">
            <ArrowRight size={18} className="text-primary" /> Representation chain
          </p>
        </div>
        <div className="p-5">
          <p className="eyebrow mb-1 flex flex-wrap items-center gap-1.5">
            <span>Input</span>
            <ArrowRight size={12} className="shrink-0" />
            <span>{encodingLabel} encoded</span>
            <ArrowRight size={12} className="shrink-0" />
            <span>Decoded</span>
          </p>
          <p className="mt-1 text-xs leading-5 text-on-surface-variant">
            Run an encode or decode to populate the chain. There is no key anywhere in this pipeline — anyone can reverse an encoding.
          </p>
          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <CodeBlock label="Original message" value={original ?? ''} />
            <CodeBlock label={`${encodingLabel} encoded`} value={encoded ?? ''} />
            <CodeBlock label="Decoded message" value={decoded ?? ''} />
          </div>
        </div>
      </Card>
    </>
  );
}

function AesModule() {
  const [plaintext, setPlaintext] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [encryptBusy, setEncryptBusy] = useState(false);
  const [encrypted, setEncrypted] = useState<AesEncryptResult | null>(null);
  const [encryptError, setEncryptError] = useState<string | null>(null);
  const [ciphertext, setCiphertext] = useState('');
  const [salt, setSalt] = useState('');
  const [iv, setIv] = useState('');
  const [tag, setTag] = useState('');
  const [decryptPassphrase, setDecryptPassphrase] = useState('');
  const [showDecryptPass, setShowDecryptPass] = useState(false);
  const [decryptBusy, setDecryptBusy] = useState(false);
  const [decrypted, setDecrypted] = useState<string | null>(null);
  const [decryptError, setDecryptError] = useState<string | null>(null);

  const runEncrypt = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (encryptBusy || decryptBusy) return;
    if (plaintext === '') {
      setEncryptError('Enter some plaintext to encrypt.');
      return;
    }
    if (passphrase.length < 8) {
      setEncryptError('Passphrase must be at least 8 characters.');
      return;
    }
    setEncryptBusy(true);
    setEncryptError(null);
    setEncrypted(null);
    try {
      const enc = await aesEncrypt(plaintext, passphrase);
      setEncrypted(enc);
      setCiphertext(enc.ciphertext);
      setSalt(enc.salt);
      setIv(enc.iv);
      setTag(enc.tag);
      setDecrypted(null);
      setDecryptError(null);
    } catch (err) {
      setEncryptError(friendlyCryptoError(err));
    } finally {
      setEncryptBusy(false);
    }
  };

  const runDecrypt = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (encryptBusy || decryptBusy) return;
    if (ciphertext === '' || salt === '' || iv === '' || tag === '') {
      setDecryptError('Enter the ciphertext, salt, nonce and tag from an encryption result.');
      return;
    }
    if (decryptPassphrase.length < 8) {
      setDecryptError('Passphrase must be at least 8 characters.');
      return;
    }
    setDecryptBusy(true);
    setDecryptError(null);
    setDecrypted(null);
    try {
      const dec = await aesDecrypt({ ciphertext, passphrase: decryptPassphrase, salt, iv, tag });
      setDecrypted(dec.plaintext);
    } catch (err) {
      setDecryptError(friendlyCryptoError(err));
    } finally {
      setDecryptBusy(false);
    }
  };

  const resetEncrypt = () => {
    setPlaintext('');
    setPassphrase('');
    setEncrypted(null);
    setEncryptError(null);
    setCiphertext('');
    setSalt('');
    setIv('');
    setTag('');
    setDecrypted(null);
    setDecryptError(null);
  };

  const resetDecrypt = () => {
    setCiphertext('');
    setSalt('');
    setIv('');
    setTag('');
    setDecryptPassphrase('');
    setDecrypted(null);
    setDecryptError(null);
  };

  const busy = encryptBusy || decryptBusy;

  return (
    <>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Encrypt</p>
          <form onSubmit={runEncrypt} className="mt-6 grid gap-4" aria-busy={busy}>
            <Field id="aes-plaintext" label="Plaintext">
              <textarea
                id="aes-plaintext"
                rows={4}
                value={plaintext}
                onChange={(e) => {
                  setPlaintext(e.target.value);
                  setEncryptError(null);
                }}
                disabled={busy}
                maxLength={4096}
                placeholder="Message to encrypt — everything stays in this browser"
                className={cn(TEXTAREA_CLASS, 'resize-none')}
              />
            </Field>
            <Field id="aes-encrypt-pass" label="Passphrase" hint="At least 8 characters. This stretches into the 256-bit AES key via PBKDF2 (600,000 iterations), so the operation takes a moment.">
              <PassphraseInput
                id="aes-encrypt-pass"
                value={passphrase}
                visible={showPass}
                disabled={busy}
                onChange={(value) => {
                  setPassphrase(value);
                  setEncryptError(null);
                }}
                onToggle={() => setShowPass((prev) => !prev)}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={busy}>
                {encryptBusy ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Deriving key &amp; encrypting…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Encrypt locally
                  </>
                )}
              </Button>
              <Button type="button" variant="secondary" onClick={resetEncrypt} disabled={busy}>
                <RotateCcw size={16} /> Reset
              </Button>
            </div>
            {encryptBusy && (
              <p className="sr-only" role="status">
                Deriving the 256-bit AES key with PBKDF2 and encrypting. Please wait.
              </p>
            )}
            {encryptError !== null && <ErrorAlert message={encryptError} />}
          </form>
        </Card>

        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Decrypt in this session</p>
          <form onSubmit={runDecrypt} className="mt-6 grid gap-4" aria-busy={busy}>
            {encrypted !== null && !encryptBusy && (
              <p className="rounded border border-success/30 bg-success/5 p-3 text-sm text-success">
                New ciphertext generated — the Decrypt fields below were filled from it automatically.
              </p>
            )}
            <Field id="aes-ciphertext" label="Ciphertext (base64)">
              <input
                id="aes-ciphertext"
                type="text"
                value={ciphertext}
                onChange={(e) => {
                  setCiphertext(e.target.value);
                  setDecryptError(null);
                }}
                disabled={busy}
                className={INPUT_CLASS}
              />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field id="aes-salt" label="Salt (base64)">
                <input
                  id="aes-salt"
                  type="text"
                  value={salt}
                  onChange={(e) => {
                    setSalt(e.target.value);
                    setDecryptError(null);
                  }}
                  disabled={busy}
                  className={INPUT_CLASS}
                />
              </Field>
              <Field id="aes-iv" label="Nonce / IV (base64)">
                <input
                  id="aes-iv"
                  type="text"
                  value={iv}
                  onChange={(e) => {
                    setIv(e.target.value);
                    setDecryptError(null);
                  }}
                  disabled={busy}
                  className={INPUT_CLASS}
                />
              </Field>
            </div>
            <Field id="aes-tag" label="Authentication tag (base64)">
              <input
                id="aes-tag"
                type="text"
                value={tag}
                onChange={(e) => {
                  setTag(e.target.value);
                  setDecryptError(null);
                }}
                disabled={busy}
                className={INPUT_CLASS}
              />
            </Field>
            <Field id="aes-decrypt-pass" label="Passphrase" hint="Use the same passphrase that encrypted the message. A wrong passphrase or any altered value is rejected by the GCM tag check.">
              <PassphraseInput
                id="aes-decrypt-pass"
                value={decryptPassphrase}
                visible={showDecryptPass}
                disabled={busy}
                onChange={(value) => {
                  setDecryptPassphrase(value);
                  setDecryptError(null);
                }}
                onToggle={() => setShowDecryptPass((prev) => !prev)}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={busy}>
                {decryptBusy ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Authenticating &amp; decrypting…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Decrypt
                  </>
                )}
              </Button>
              <Button type="button" variant="secondary" onClick={resetDecrypt} disabled={busy}>
                <RotateCcw size={16} /> Reset
              </Button>
            </div>
            {decryptBusy && (
              <p className="sr-only" role="status">
                Deriving the key with PBKDF2 and authenticating the ciphertext. Please wait.
              </p>
            )}
            {decryptError !== null && <ErrorAlert message={decryptError} />}
            {decrypted !== null && (
              <div className="mt-2">
                <div className="flex items-center gap-2 rounded border border-success/30 bg-success/5 p-3 text-sm text-success">
                  <CheckCircle size={16} className="shrink-0" />
                  <p>Decryption succeeded — the GCM integrity check passed.</p>
                </div>
                <div className="mt-4">
                  <CodeBlock label="Decrypted plaintext" value={decrypted} />
                </div>
              </div>
            )}
          </form>
        </Card>
      </div>

      {encrypted !== null && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold flex items-center gap-2">
              <ShieldCheck size={18} className="text-success" /> Encryption output
            </p>
          </div>
          <div className="grid gap-3 p-5 sm:grid-cols-2 lg:grid-cols-4">
            <MetricTile label="Key size" value="AES-256 · 256-bit key" />
            <MetricTile label="Key derivation" value={AES_KEY_DERIVATION} />
            <MetricTile label="Authentication" value="GCM · 128-bit tag" />
            <MetricTile label="Entropy" value="Fresh 16-byte salt + 12-byte nonce per run" />
          </div>
          <div className="grid gap-4 p-5 lg:grid-cols-2">
            <CodeBlock label="Ciphertext (base64)" value={encrypted.ciphertext} />
            <CodeBlock label="Salt (base64)" value={encrypted.salt} />
            <CodeBlock label="Nonce / IV (base64)" value={encrypted.iv} />
            <CodeBlock label="Authentication tag (base64)" value={encrypted.tag} />
          </div>
          <p className="px-5 pb-5 text-xs leading-5 text-on-surface-variant">
            These values exist only in this page’s memory. Combine them with the passphrase in the Decrypt card to reverse the operation during this session. Nothing is persisted, sent to the backend, or placed in a URL.
          </p>
        </Card>
      )}
    </>
  );
}

function HmacModule() {
  const [message, setMessage] = useState('');
  const [keyInput, setKeyInput] = useState('');
  const [keyFormat, setKeyFormat] = useState<HmacKeyFormat>('hex');
  const [generatedKey, setGeneratedKey] = useState<HmacKeyMaterial | null>(null);
  const [signing, setSigning] = useState(false);
  const [signingError, setSigningError] = useState<string | null>(null);
  const [signResult, setSignResult] = useState<HmacSignResult | null>(null);
  const [macInput, setMacInput] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<HmacVerifyResult | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const busy = signing || verifying;

  const generateKey = async () => {
    const material = await hmacGenerateKey(32);
    setGeneratedKey(material);
    setKeyInput(material.keyHex);
    setKeyFormat('hex');
    setVerifyResult(null);
    setSigningError(null);
    setVerifyError(null);
  };

  const runSign = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (busy) return;
    if (message === '') {
      setSigningError('Enter a message to tag.');
      return;
    }
    if (keyInput === '') {
      setSigningError('Generate a shared secret or paste a key in hex/base64 first.');
      return;
    }
    setSigning(true);
    setSigningError(null);
    setVerifyResult(null);
    try {
      const cryptoKey = await hmacImportKey(keyInput, keyFormat === 'raw' ? 'base64' : keyFormat);
      const sig = await hmacSign(message, cryptoKey);
      setSignResult(sig);
      setMacInput(sig.mac);
    } catch (err) {
      setSigningError(friendlyCryptoError(err));
    } finally {
      setSigning(false);
    }
  };

  const runVerify = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (busy) return;
    if (message === '') {
      setVerifyError('Enter the message that was signed.');
      return;
    }
    if (keyInput === '') {
      setVerifyError('Generate a shared secret or paste a key in hex/base64 first.');
      return;
    }
    if (macInput === '') {
      setVerifyError('Paste the HMAC tag you want to verify.');
      return;
    }
    setVerifying(true);
    setVerifyError(null);
    setVerifyResult(null);
    try {
      const cryptoKey = await hmacImportKey(keyInput, keyFormat === 'raw' ? 'base64' : keyFormat);
      const verified = await hmacVerify(message, macInput, cryptoKey);
      setVerifyResult(verified);
    } catch (err) {
      setVerifyError(friendlyCryptoError(err));
    } finally {
      setVerifying(false);
    }
  };

  const reset = () => {
    setMessage('');
    setKeyInput('');
    setGeneratedKey(null);
    setSignResult(null);
    setMacInput('');
    setVerifyResult(null);
    setSigningError(null);
    setVerifyError(null);
  };

  return (
    <>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Message &amp; shared secret</p>
          <form onSubmit={runSign} className="mt-6 grid gap-4" aria-busy={busy}>
            <Field id="hmac-message" label="Message" hint="HMAC does not hide this message — anyone can read it. The tag only proves who could have written it.">
              <textarea
                id="hmac-message"
                rows={3}
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  setSigningError(null);
                  setVerifyError(null);
                }}
                disabled={busy}
                maxLength={4096}
                placeholder="Message to authenticate, e.g. amount=100&recipient=alice"
                className={cn(TEXTAREA_CLASS, 'resize-none')}
              />
            </Field>
            <Field id="hmac-key" label="Shared secret (hex or base64)">
              <input
                id="hmac-key"
                type="text"
                value={keyInput}
                onChange={(e) => {
                  setKeyInput(e.target.value);
                  setSigningError(null);
                  setVerifyError(null);
                }}
                disabled={busy}
                maxLength={512}
                placeholder="Paste a key or generate one below"
                aria-describedby="hmac-key-hint"
                className={INPUT_CLASS}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="secondary" onClick={() => void generateKey()} disabled={busy}>
                <Sparkles size={16} /> Generate 256-bit secret
              </Button>
              <Button type="submit" disabled={busy}>
                {signing ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Signing…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Generate tag
                  </>
                )}
              </Button>
              <Button type="button" variant="secondary" onClick={reset} disabled={busy}>
                <RotateCcw size={16} /> Reset
              </Button>
            </div>
            <p id="hmac-key-hint" className="text-xs leading-5 text-on-surface-variant">
              {generatedKey !== null
                ? 'Key generated from crypto.getRandomValues() — 256 bits of entropy. Keep it secret.'
                : 'The generated secret uses cryptographically secure randomness. You should not reuse it elsewhere.'}
            </p>
            {signingError !== null && <ErrorAlert message={signingError} />}
          </form>
          {signResult !== null && (
            <div className="mt-5">
              <CodeBlock label="HMAC-SHA256 tag" value={signResult.mac} />
            </div>
          )}
        </Card>

        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Verify a tag</p>
          <form onSubmit={runVerify} className="mt-6 grid gap-4" aria-busy={busy}>
            <p className="text-xs leading-5 text-on-surface-variant">
              Verification uses the message and shared secret from the left card. Edit either one — or paste an external tag — then verify to observe tamper detection.
            </p>
            <Field id="hmac-mac" label="Tag to verify (hex)">
              <input
                id="hmac-mac"
                type="text"
                value={macInput}
                onChange={(e) => {
                  setMacInput(e.target.value);
                  setVerifyError(null);
                  setVerifyResult(null);
                }}
                disabled={busy}
                maxLength={256}
                placeholder="64 hex characters"
                className={INPUT_CLASS}
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={busy}>
                {verifying ? (
                  <>
                    <Loader2 size={16} className="animate-spin" /> Verifying…
                  </>
                ) : (
                  <>
                    <Play size={16} /> Verify tag
                  </>
                )}
              </Button>
            </div>
            {verifyError !== null && <ErrorAlert message={verifyError} />}
            {verifyResult !== null && (
              <div className="mt-2">
                {verifyResult.valid ? (
                  <div className="rounded border border-success/30 bg-success/5 p-3">
                    <div className="flex items-center gap-2 text-sm text-success">
                      <ShieldCheck size={16} className="shrink-0" />
                      <p className="font-medium">Tag is valid</p>
                    </div>
                    <p className="mt-2 text-xs leading-5 text-on-surface-variant">
                      The tag was produced with this exact message and shared secret, and neither changed since signing.
                    </p>
                  </div>
                ) : (
                  <div className="rounded border border-danger/30 bg-danger/5 p-3">
                    <div className="flex items-center gap-2 text-sm text-danger">
                      <XCircle size={16} className="shrink-0" />
                      <p className="font-medium">Tag is invalid</p>
                    </div>
                    <p className="mt-2 text-xs leading-5 text-on-surface-variant">
                      The message, the secret, or the tag differs from what was signed. Integrity or authenticity cannot be confirmed.
                    </p>
                  </div>
                )}
              </div>
            )}
          </form>
        </Card>
      </div>
    </>
  );
}

function RandomModule() {
  const [size, setSize] = useState(32);
  const [result, setResult] = useState<RandomBytesResult | null>(null);

  const generate = () => {
    setResult(generateRandomBytes(size));
  };

  const reset = () => {
    setResult(null);
  };

  return (
    <>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Draw random bytes</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              generate();
            }}
            className="mt-6 grid gap-4"
          >
            <Field id="random-size" label="Byte count">
              <select id="random-size" value={size} onChange={(e) => setSize(Number(e.target.value))} className={SELECT_CLASS}>
                <option value={16}>16 bytes · 128 bits</option>
                <option value={24}>24 bytes · 192 bits</option>
                <option value={32}>32 bytes · 256 bits</option>
                <option value={48}>48 bytes · 384 bits</option>
                <option value={64}>64 bytes · 512 bits</option>
              </select>
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button type="submit">
                <RefreshCw size={16} /> Generate bytes
              </Button>
              <Button type="button" variant="secondary" onClick={reset} disabled={result === null}>
                <RotateCcw size={16} /> Clear
              </Button>
            </div>
            <p className="text-xs leading-5 text-on-surface-variant">
              Drawn with <code className="font-mono">crypto.getRandomValues()</code> — the platform CSPRNG. This is the same source used for the salts, nonces and keys elsewhere in the lab.
            </p>
          </form>
        </Card>

        <Card className="p-5">
          {result !== null ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Random bytes</p>
                  <p className="mt-2 font-display text-xl font-bold text-on-surface">{result.lengthBytes} bytes</p>
                </div>
                <Badge tone="success">
                  <ShieldCheck size={12} className="mr-1" /> CSPRNG
                </Badge>
              </div>
              <div className="mt-6 grid gap-4">
                <CodeBlock label="Hex" value={result.hex} />
                <CodeBlock label="Base64" value={result.base64} />
              </div>
              <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-on-surface-variant">
                <Info size={14} className="mt-0.5 shrink-0" />
                <span>
                  These bytes are only for experimentation and exist solely in page memory. Every draw produces a new, unpredictable value.
                </span>
              </p>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Random bytes</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Output</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  Generate bytes to inspect hex and Base64 representations of cryptographically secure randomness.
                </p>
              </div>
            </>
          )}
        </Card>
      </div>
    </>
  );
}

export function CryptographyLabPage() {
  const [activeModule, setActiveModule] = useState<CryptoModuleId>('hashing');
  const webCryptoSupported = isWebCryptoSupported();
  const active = cryptoModules.find((module) => module.id === activeModule);
  const ActiveIcon = active?.icon ?? ShieldCheck;

  return (
    <>
      <PageHeader
        eyebrow="Security lab"
        title="Cryptography Lab"
        description="Experiment with real cryptographic primitives directly in your browser and learn what they actually provide."
      />

      <Card className="border-warning/40 bg-warning/5 p-5">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 shrink-0 text-warning" size={20} />
          <div>
            <p className="font-display font-semibold">Kept private in your browser</p>
            <ul className="mt-2 space-y-1.5 text-sm leading-6 text-on-surface-variant">
              <li>All hashing, encoding, AES-256-GCM encryption and HMAC operations run locally with the Web Crypto API.</li>
              <li>Plaintext, passphrases and keys are never sent to the backend, persisted, logged, or placed in any URL.</li>
              <li>Refreshing or leaving this page immediately clears every transient value.</li>
              <li>This is an educational lab — never enter real passwords, production secrets, or data you cannot afford to lose.</li>
            </ul>
          </div>
        </div>
      </Card>

      {!webCryptoSupported ? (
        <Card className="mt-5 border-danger/40 bg-danger/5 p-5">
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-0.5 shrink-0 text-danger" size={20} />
            <div>
              <p className="font-display font-semibold text-danger">Web Crypto API is unavailable</p>
              <p className="mt-1 text-sm leading-6 text-on-surface-variant">
                This browser or environment does not expose the Web Crypto API (<code className="font-mono">crypto.subtle</code>), which every lab operation relies on. Try an up-to-date browser in a secure (HTTPS) context.
              </p>
            </div>
          </div>
        </Card>
      ) : (
        <>
          <Card className="mt-5">
            <div className="border-b px-5 py-4">
              <p className="font-display font-semibold flex items-center gap-2">
                <Layers size={18} className="text-primary" /> Lab modules
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2 p-4 sm:grid-cols-3 lg:grid-cols-5">
              {cryptoModules.map((module) => {
                const Icon = module.icon;
                const selected = module.id === activeModule;
                return (
                  <button
                    key={module.id}
                    type="button"
                    onClick={() => setActiveModule(module.id)}
                    aria-pressed={selected}
                    className={cn(
                      'flex items-center justify-center gap-2 rounded border px-3 py-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60',
                      selected
                        ? 'border-primary/40 bg-primary/10 text-primary'
                        : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
                    )}
                  >
                    <Icon size={16} /> {module.label}
                  </button>
                );
              })}
            </div>
          </Card>

          {active !== undefined && (
            <Card className="mt-5 p-5">
              <div className="flex items-start gap-3">
                <ActiveIcon className="mt-0.5 shrink-0 text-primary" size={20} />
                <div>
                  <p className="eyebrow mb-1">Selected module</p>
                  <p className="font-display text-lg font-semibold">{active.short}</p>
                  <ul className="mt-3 grid gap-1.5 text-sm leading-6 text-on-surface-variant sm:grid-cols-2">
                    {active.teaches.map((item) => (
                      <li key={item} className="flex items-start gap-2">
                        <CheckCircle size={14} className="mt-1 shrink-0 text-primary" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </Card>
          )}

          {activeModule === 'hashing' && <HashingModule />}
          {activeModule === 'encoding' && <EncodingModule />}
          {activeModule === 'aes' && <AesModule />}
          {activeModule === 'hmac' && <HmacModule />}
          {activeModule === 'random' && <RandomModule />}

          <Card className="mt-5">
            <div className="border-b px-5 py-4">
              <p className="font-display font-semibold flex items-center gap-2">
                <Info size={18} className="text-primary" /> What this module teaches
              </p>
            </div>
            <div className="divide-y p-5">
              {cryptoConcepts[activeModule].map((item) => (
                <ConceptItem key={item.title} title={item.title} body={item.body} />
              ))}
            </div>
          </Card>
        </>
      )}
    </>
  );
}