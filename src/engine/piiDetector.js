import { detectCardNetwork, isValidLuhn, normalizeCardDigits } from './luhn.js';

/**
 * Canonical PII category metadata shared across detector, redactor, and UI.
 */
export const PII_TYPES = {
  EMAIL: {
    id: 'EMAIL',
    label: 'Emails',
    shortLabel: 'Email',
    prefix: 'EMAIL',
    fullMaskToken: '[REDACTED_EMAIL]',
    validationMethod: 'RFC-5322 Syntax',
    badgeClass:
      'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30',
    highlightClass:
      'bg-sky-500/20 text-sky-900 dark:text-sky-200 ring-1 ring-sky-500/40',
    dotClass: 'bg-sky-500',
  },
  PHONE: {
    id: 'PHONE',
    label: 'Phones',
    shortLabel: 'Phone',
    prefix: 'PHONE',
    fullMaskToken: '[REDACTED_PHONE]',
    validationMethod: 'E.164 / NANP / IN Format',
    badgeClass:
      'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30',
    highlightClass:
      'bg-violet-500/20 text-violet-900 dark:text-violet-200 ring-1 ring-violet-500/40',
    dotClass: 'bg-violet-500',
  },
  IP_ADDRESS: {
    id: 'IP_ADDRESS',
    label: 'IP Addresses',
    shortLabel: 'IP',
    prefix: 'IP',
    fullMaskToken: '[REDACTED_IP]',
    validationMethod: 'IPv4 (0–255) / IPv6 RFC-4291',
    badgeClass:
      'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
    highlightClass:
      'bg-amber-500/20 text-amber-900 dark:text-amber-200 ring-1 ring-amber-500/40',
    dotClass: 'bg-amber-500',
  },
  PAN: {
    id: 'PAN',
    label: 'Indian PAN',
    shortLabel: 'PAN',
    prefix: 'PAN',
    fullMaskToken: '[REDACTED_PAN]',
    validationMethod: 'PAN Entity Code [PCHABGJLFT]',
    badgeClass:
      'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
    highlightClass:
      'bg-rose-500/20 text-rose-900 dark:text-rose-200 ring-1 ring-rose-500/40',
    dotClass: 'bg-rose-500',
  },
  AADHAAR: {
    id: 'AADHAAR',
    label: 'Aadhaar',
    shortLabel: 'Aadhaar',
    prefix: 'AADHAAR',
    fullMaskToken: '[REDACTED_AADHAAR]',
    validationMethod: 'UIDAI 12-Digit Rule (^[2-9])',
    badgeClass:
      'bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30',
    highlightClass:
      'bg-fuchsia-500/20 text-fuchsia-900 dark:text-fuchsia-200 ring-1 ring-fuchsia-500/40',
    dotClass: 'bg-fuchsia-500',
  },
  CREDIT_CARD: {
    id: 'CREDIT_CARD',
    label: 'Credit Cards',
    shortLabel: 'Card',
    prefix: 'CARD',
    fullMaskToken: '[REDACTED_CARD]',
    validationMethod: 'Luhn Mod-10 Checksum',
    badgeClass:
      'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
    highlightClass:
      'bg-emerald-500/20 text-emerald-900 dark:text-emerald-200 ring-1 ring-emerald-500/40',
    dotClass: 'bg-emerald-500',
  },
};

export const PII_TYPE_ORDER = [
  'EMAIL',
  'PHONE',
  'IP_ADDRESS',
  'PAN',
  'AADHAAR',
  'CREDIT_CARD',
];

const TYPE_PRIORITY = {
  CREDIT_CARD: 6,
  AADHAAR: 5,
  PAN: 4,
  EMAIL: 3,
  IP_ADDRESS: 2,
  PHONE: 1,
};

/**
 * Validates RFC-4291 IPv6 literal strings (full or :: compressed) while
 * rejecting timestamps like 12:34:56 and MAC addresses like 00:1A:2B:3C:4D:5E.
 * @param {string} value
 * @returns {boolean}
 */
export function isValidIPv6(value) {
  if (!value || value.includes(':::')) return false;
  const doubleColonParts = value.split('::');
  if (doubleColonParts.length > 2) return false;

  const isHexGroup = (g) => /^[0-9A-Fa-f]{1,4}$/.test(g);

  if (doubleColonParts.length === 1) {
    const groups = value.split(':');
    return groups.length === 8 && groups.every(isHexGroup);
  }

  const [leftRaw, rightRaw] = doubleColonParts;
  const leftGroups = leftRaw ? leftRaw.split(':') : [];
  const rightGroups = rightRaw ? rightRaw.split(':') : [];
  const totalGroups = leftGroups.length + rightGroups.length;

  // Require at least one non-empty hextet so bare "::" is ignored
  if (totalGroups === 0 || totalGroups >= 8) return false;

  return leftGroups.every(isHexGroup) && rightGroups.every(isHexGroup);
}

/**
 * Validates email structure beyond regex (TLD length, no consecutive dots).
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  if (email.length > 254) return false;
  const atIndex = email.indexOf('@');
  if (atIndex <= 0) return false;
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex + 1);
  if (local.length > 64 || local.includes('..') || domain.includes('..')) {
    return false;
  }
  const domainParts = domain.split('.');
  const tld = domainParts[domainParts.length - 1];
  return /^[A-Za-z]{2,24}$/.test(tld);
}

/**
 * Validates phone candidates to prevent matching dates, IPs, or short IDs.
 * @param {string} raw
 * @returns {boolean}
 */
function isValidPhone(raw) {
  const openCount = (raw.match(/\(/g) || []).length;
  const closeCount = (raw.match(/\)/g) || []).length;
  if (openCount !== closeCount) return false;

  const digits = raw.replace(/\D/g, '');
  if (raw.startsWith('+')) {
    return digits.length >= 10 && digits.length <= 15;
  }
  return digits.length === 10 || (digits.length === 11 && digits.startsWith('0'));
}

/**
 * Runs deterministic PII detection across all supported categories.
 * Returns non-overlapping matches sorted by start offset plus Luhn rejection count.
 *
 * @param {string} text
 * @returns {{
 *   matches: Array<{
 *     start: number,
 *     end: number,
 *     type: string,
 *     value: string,
 *     isValid: boolean,
 *     validationMethod: string,
 *   }>,
 *   luhnRejectedCount: number,
 *   countsByType: Record<string, number>,
 *   totalDetected: number,
 * }}
 */
export function detectPII(text) {
  const emptyCounts = Object.fromEntries(PII_TYPE_ORDER.map((t) => [t, 0]));
  if (!text || typeof text !== 'string') {
    return {
      matches: [],
      luhnRejectedCount: 0,
      countsByType: emptyCounts,
      totalDetected: 0,
    };
  }

  const candidates = [];
  let luhnRejectedCount = 0;

  // 1. Emails (start with alphanumeric; exclude '=' from local-part so log key=email pairs stay intact)
  const emailRegex =
    /(?<![A-Za-z0-9._%+-])[A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/?^_`{|}~-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![A-Za-z0-9._%+-])/g;
  for (const m of text.matchAll(emailRegex)) {
    const value = m[0];
    if (isValidEmail(value)) {
      candidates.push({
        start: m.index,
        end: m.index + value.length,
        type: 'EMAIL',
        value,
        isValid: true,
        validationMethod: PII_TYPES.EMAIL.validationMethod,
      });
    }
  }

  // 2. Credit Cards + Luhn Gate (13-19 digits, grouped or contiguous)
  const cardRegex =
    /(?<![\dA-Za-z+-])(?:\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,4})?|\d{4}[ -]\d{6}[ -]\d{4,5}|\d{13,19})(?![\dA-Za-z-])/g;
  for (const m of text.matchAll(cardRegex)) {
    const value = m[0];
    const digits = normalizeCardDigits(value);
    if (digits.length < 13 || digits.length > 19) continue;

    if (isValidLuhn(value)) {
      const network = detectCardNetwork(value);
      candidates.push({
        start: m.index,
        end: m.index + value.length,
        type: 'CREDIT_CARD',
        value,
        isValid: true,
        validationMethod: `Luhn Mod-10 (${network})`,
      });
    } else {
      luhnRejectedCount += 1;
    }
  }

  // 3. Indian PAN (exact 10 chars with valid 4th-char entity code)
  const panRegex =
    /(?<![A-Za-z0-9])[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z](?![A-Za-z0-9])/g;
  for (const m of text.matchAll(panRegex)) {
    const value = m[0];
    candidates.push({
      start: m.index,
      end: m.index + value.length,
      type: 'PAN',
      value,
      isValid: true,
      validationMethod: PII_TYPES.PAN.validationMethod,
    });
  }

  // 4. Indian Aadhaar (12 digits, XXXX XXXX XXXX or XXXXXXXXXXXX, leading 2-9)
  const aadhaarRegex =
    /(?<!\d{4}[ -])(?<![\dA-Za-z.-])(?:[2-9]\d{3}\s\d{4}\s\d{4}(?![ -]\d{4})|[2-9]\d{11})(?![\dA-Za-z.-])/g;
  for (const m of text.matchAll(aadhaarRegex)) {
    const value = m[0];
    candidates.push({
      start: m.index,
      end: m.index + value.length,
      type: 'AADHAAR',
      value,
      isValid: true,
      validationMethod: PII_TYPES.AADHAAR.validationMethod,
    });
  }

  // 5. IPv4 (strict 0-255 per octet; rejects version numbers like v2.4.1.0)
  const ipv4Regex =
    /(?<![\dA-Za-z.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\dA-Za-z.])/g;
  for (const m of text.matchAll(ipv4Regex)) {
    const value = m[0];
    const precedingContext = text.slice(Math.max(0, m.index - 12), m.index);
    if (/\b(?:ver|version|release)[\s:=]+$/i.test(precedingContext)) {
      continue;
    }
    candidates.push({
      start: m.index,
      end: m.index + value.length,
      type: 'IP_ADDRESS',
      value,
      isValid: true,
      validationMethod: 'IPv4 (0–255 Octets)',
    });
  }

  // 6. IPv6
  const ipv6Regex =
    /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])/g;
  for (const m of text.matchAll(ipv6Regex)) {
    const value = m[0];
    if (isValidIPv6(value)) {
      candidates.push({
        start: m.index,
        end: m.index + value.length,
        type: 'IP_ADDRESS',
        value,
        isValid: true,
        validationMethod: 'IPv6 (RFC-4291)',
      });
    }
  }

  // 7. Phone Numbers (Intl +CC, parenthesized, hyphenated, and IN 10-digit)
  const phoneRegex =
    /(?<![\dA-Za-z+-])(?:\+\d{1,3}(?:[\s.-]?\(?\d{1,5}\)?){1,4}|\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}|\d{3}[-.]\d{3}[-.]\d{4}|(?:0?[6-9]\d{4}[-\s]\d{5})|[6-9]\d{9})(?![\dA-Za-z-])/g;
  for (const m of text.matchAll(phoneRegex)) {
    const value = m[0];
    if (isValidPhone(value)) {
      candidates.push({
        start: m.index,
        end: m.index + value.length,
        type: 'PHONE',
        value,
        isValid: true,
        validationMethod: PII_TYPES.PHONE.validationMethod,
      });
    }
  }

  // Overlap resolution: sort by start ascending, length descending, priority descending
  candidates.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return (TYPE_PRIORITY[b.type] || 0) - (TYPE_PRIORITY[a.type] || 0);
  });

  const matches = [];
  let lastEnd = -1;
  for (const candidate of candidates) {
    if (candidate.start >= lastEnd) {
      matches.push(candidate);
      lastEnd = candidate.end;
    }
  }

  const countsByType = { ...emptyCounts };
  for (const match of matches) {
    countsByType[match.type] = (countsByType[match.type] || 0) + 1;
  }

  return {
    matches,
    luhnRejectedCount,
    countsByType,
    totalDetected: matches.length,
  };
}
