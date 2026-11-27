/**
 * Standalone Luhn (Mod-10) checksum validator for payment card numbers.
 * Runs 100% client-side with zero external dependencies.
 */

/**
 * Strips spaces and hyphens from a candidate card string.
 * @param {string} raw
 * @returns {string}
 */
export function normalizeCardDigits(raw) {
  return String(raw ?? '').replace(/[\s-]/g, '');
}

/**
 * Validates a candidate credit/debit card number using the Luhn Mod-10 algorithm.
 * Rejects non-13..19 digit strings and all-zero sequences.
 * @param {string} raw
 * @returns {boolean}
 */
export function isValidLuhn(raw) {
  const digits = normalizeCardDigits(raw);
  if (!/^\d{13,19}$/.test(digits)) {
    return false;
  }
  if (/^0+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Identifies probable card network from IIN/BIN prefix for audit tooltips.
 * @param {string} raw
 * @returns {string}
 */
export function detectCardNetwork(raw) {
  const digits = normalizeCardDigits(raw);
  if (/^4/.test(digits)) return 'Visa';
  if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(digits)) {
    return 'Mastercard';
  }
  if (/^3[47]/.test(digits)) return 'American Express';
  if (/^(6011|652[12])/.test(digits)) return 'Discover / RuPay';
  if (/^(60|65|81|82)/.test(digits)) return 'RuPay / Discover';
  return 'Payment Card';
}
