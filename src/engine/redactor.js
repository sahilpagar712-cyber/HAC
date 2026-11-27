import { normalizeCardDigits } from './luhn.js';
import { PII_TYPES, PII_TYPE_ORDER } from './piiDetector.js';

export const REDACTION_MODES = {
  FULL_MASK: 'FULL_MASK',
  PARTIAL_MASK: 'PARTIAL_MASK',
  PSEUDONYM: 'PSEUDONYM',
};

/**
 * Creates a fresh deterministic in-memory pseudonymization session store.
 */
export function createPseudonymSession() {
  return {
    map: new Map(), // key: `${type}::${rawValue}` -> { placeholder, rawValue, type }
    counters: Object.fromEntries(PII_TYPE_ORDER.map((t) => [t, 0])),
  };
}

/**
 * Formats a partial mask retaining safe verification context per entity type.
 * @param {string} type
 * @param {string} value
 * @returns {string}
 */
export function formatPartialMask(type, value) {
  switch (type) {
    case 'EMAIL': {
      const atIdx = value.indexOf('@');
      if (atIdx <= 0) return '***@***';
      const local = value.slice(0, atIdx);
      const domain = value.slice(atIdx + 1);
      return `${local[0]}***@${domain}`;
    }
    case 'PHONE': {
      const ccMatch = value.match(/^(\+\d{1,3})[\s.-]/);
      if (ccMatch) {
        const cc = ccMatch[1];
        const restDigits = value.slice(cc.length).replace(/\D/g, '');
        const last4 = restDigits.slice(-4);
        const maskLen = Math.max(4, restDigits.length - 4);
        return `${cc}-${'X'.repeat(maskLen)}${last4}`;
      }
      const digits = value.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      if (value.startsWith('+') && digits.length > 10) {
        const ccLen = digits.length - 10;
        const cc = `+${digits.slice(0, ccLen)}`;
        return `${cc}-${'X'.repeat(6)}${last4}`;
      }
      const maskLen = Math.max(4, digits.length - 4);
      return `${'X'.repeat(maskLen)}${last4}`;
    }
    case 'IP_ADDRESS': {
      if (value.includes(':')) {
        const parts = value.split(':').filter((p, idx, arr) => p !== '' || idx < 2 || idx === arr.length - 1);
        const prefix = parts.slice(0, 2).join(':') || '::';
        return `${prefix}:****:****`;
      }
      const octets = value.split('.');
      if (octets.length === 4) {
        return `${octets[0]}.${octets[1]}.***.***`;
      }
      return '***.***.***.***';
    }
    case 'PAN': {
      return `${value.slice(0, 5)}****${value.slice(-1)}`;
    }
    case 'AADHAAR': {
      const digits = value.replace(/\D/g, '');
      return `XXXX-XXXX-${digits.slice(-4)}`;
    }
    case 'CREDIT_CARD': {
      const digits = normalizeCardDigits(value);
      return `XXXX-XXXX-XXXX-${digits.slice(-4)}`;
    }
    default:
      return '[REDACTED]';
  }
}

/**
 * Resolves a replacement token for a single matched PII entity.
 * Updates the session pseudonym map when in PSEUDONYM mode.
 *
 * @param {{ type: string, value: string }} match
 * @param {string} mode
 * @param {object} options
 * @param {boolean} [options.uniformFullMask]
 * @param {ReturnType<createPseudonymSession>} [options.session]
 * @returns {string}
 */
function resolveReplacement(match, mode, options) {
  const { uniformFullMask = false, session } = options;

  if (mode === REDACTION_MODES.FULL_MASK) {
    if (uniformFullMask) return '[REDACTED]';
    return PII_TYPES[match.type]?.fullMaskToken || '[REDACTED]';
  }

  if (mode === REDACTION_MODES.PARTIAL_MASK) {
    return formatPartialMask(match.type, match.value);
  }

  if (mode === REDACTION_MODES.PSEUDONYM) {
    const activeSession = session || createPseudonymSession();
    const key = `${match.type}::${match.value}`;
    const existing = activeSession.map.get(key);
    if (existing) {
      return existing.placeholder;
    }
    const nextNum = (activeSession.counters[match.type] || 0) + 1;
    activeSession.counters[match.type] = nextNum;
    const prefix = PII_TYPES[match.type]?.prefix || match.type;
    const placeholder = `${prefix}_${String(nextNum).padStart(2, '0')}`;
    activeSession.map.set(key, {
      key,
      placeholder,
      rawValue: match.value,
      type: match.type,
    });
    return placeholder;
  }

  return '[REDACTED]';
}

/**
 * Transforms source text using non-overlapping matches and returns both
 * the sanitized string and synchronized diff segments.
 *
 * @param {string} text
 * @param {Array} matches - Sorted, non-overlapping matches from detectPII
 * @param {{
 *   mode: string,
 *   uniformFullMask?: boolean,
 *   session?: ReturnType<createPseudonymSession>,
 * }} options
 */
export function redactText(text, matches, options = {}) {
  const {
    mode = REDACTION_MODES.FULL_MASK,
    uniformFullMask = false,
    session = null,
  } = options;

  if (!text) {
    return {
      sanitizedText: '',
      segments: [],
      redactedCount: 0,
    };
  }

  const segments = [];
  const outputChunks = [];
  let cursor = 0;

  for (const match of matches) {
    if (match.start > cursor) {
      const plain = text.slice(cursor, match.start);
      segments.push({
        kind: 'text',
        originalText: plain,
        sanitizedText: plain,
      });
      outputChunks.push(plain);
    }

    const replacement = resolveReplacement(match, mode, {
      uniformFullMask,
      session,
    });

    segments.push({
      kind: 'entity',
      originalText: match.value,
      sanitizedText: replacement,
      match,
    });
    outputChunks.push(replacement);
    cursor = match.end;
  }

  if (cursor < text.length) {
    const tail = text.slice(cursor);
    segments.push({
      kind: 'text',
      originalText: tail,
      sanitizedText: tail,
    });
    outputChunks.push(tail);
  }

  return {
    sanitizedText: outputChunks.join(''),
    segments,
    redactedCount: matches.length,
  };
}
