/**
 * Deterministic initials helper — no dependencies.
 * Defensive against null/undefined/empty/whitespace/unusual emails.
 *
 * Examples:
 *  "Simran Sharma" -> "SS"
 *  "Simran" -> "S"
 *  "John Michael Smith" -> "JS"  (first + last)
 */
export function getInitials(displayName: string | null | undefined, fallbackEmail?: string | null): string {
  const raw = typeof displayName === 'string' ? displayName.trim() : '';
  let base = raw;

  if (!base && typeof fallbackEmail === 'string' && fallbackEmail.trim().length > 0) {
    const email = fallbackEmail.trim();
    // Use local-part before @ if present, else full email
    const local = email.includes('@') ? (email.split('@')[0] ?? '') : email;
    base = local.trim();
    // If local-part empty (e.g. "@example.com"), fallback to email itself
    if (!base) base = email.trim();
  }

  if (!base) return '?';

  // Split on whitespace; filter empty
  const parts = base.split(/\s+/).filter(Boolean);

  if (parts.length === 0) return '?';

  if (parts.length === 1) {
    const single = parts[0] ?? '';
    // Handle single token that may contain separators like . _ - for email local-part
    // e.g. "john.doe" -> JD, "john_doe" -> JD, but spec prefers single char for "Simran"
    // We treat dot/underscore/hyphen as word separators only if they clearly separate names
    // To keep spec example "Simran" -> "S", we only split on . _ - if it yields meaningful parts
    if (/[._-]/.test(single) && single.length > 2) {
      const subParts = single.split(/[._-]+/).filter(Boolean);
      if (subParts.length >= 2) {
        const first = subParts[0]?.charAt(0) ?? '';
        const last = subParts[subParts.length - 1]?.charAt(0) ?? '';
        const init = (first + last).toUpperCase();
        if (init.trim().length > 0) return init;
      }
    }
    return (single.charAt(0) ?? '?').toUpperCase();
  }

  // 2+ parts: first + last (ignores middle names) — matches "John Michael Smith" -> "JS"
  const first = parts[0]?.charAt(0) ?? '';
  const last = parts[parts.length - 1]?.charAt(0) ?? '';
  const combined = (first + last).toUpperCase();
  if (combined.trim().length === 0) return '?';
  return combined;
}

/**
 * Resolve display name per spec:
 *  profile.full_name -> user.name -> user.email local-part
 */
export function getDisplayName(
  profileFullName: string | null | undefined,
  userName: string | null | undefined,
  email: string | null | undefined,
): string {
  if (typeof profileFullName === 'string' && profileFullName.trim().length > 0) {
    return profileFullName.trim();
  }
  if (typeof userName === 'string' && userName.trim().length > 0) {
    return userName.trim();
  }
  if (typeof email === 'string' && email.trim().length > 0) {
    const trimmed = email.trim();
    if (trimmed.includes('@')) {
      const local = trimmed.split('@')[0] ?? '';
      if (local.trim().length > 0) return local.trim();
    }
    return trimmed;
  }
  return '';
}

export function getEmailLocalPart(email: string | null | undefined): string {
  if (typeof email !== 'string' || email.trim().length === 0) return '';
  const t = email.trim();
  if (t.includes('@')) return (t.split('@')[0] ?? '').trim();
  return t;
}
