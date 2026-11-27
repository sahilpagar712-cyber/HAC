/**
 * Client-side Browser Privacy & Local Password Strength Scanner.
 * - Passwords are evaluated 100% locally in browser memory (never sent to backend or logged).
 * - Cookies & storage inspect only the current origin (names & byte sizes, never private values).
 * - Permissions use the read-only navigator.permissions.query API without triggering hardware prompts.
 */

const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
  'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
  'ashley', 'michael', 'shadow', '123123', '654321', '000000', 'password1',
  'admin', 'admin123', 'root', 'toor', 'pass', 'test', 'guest', 'welcome',
]);

export function evaluatePasswordLocally(password) {
  if (!password) return null;

  const length = password.length;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password);

  let score = 0;
  const suggestions = [];

  if (length >= 8) {
    score += 1;
  } else {
    suggestions.push('Use at least 8 characters (12+ recommended).');
  }

  if (length >= 12) {
    score += 1;
  } else if (length >= 8) {
    suggestions.push('Increase length to 12+ characters for stronger entropy.');
  }

  if (hasUpper && hasLower) {
    score += 1;
  } else {
    if (!hasUpper) suggestions.push('Include uppercase letters (A-Z).');
    if (!hasLower) suggestions.push('Include lowercase letters (a-z).');
  }

  if (hasDigit) {
    score += 0.5;
  } else {
    suggestions.push('Include numeric digits (0-9).');
  }

  if (hasSpecial) {
    score += 0.5;
  } else {
    suggestions.push('Include special symbols (!@#$%...).');
  }

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    score = Math.max(0, score - 2);
    suggestions.unshift('Avoid common dictionary passwords.');
  }

  if (/(.)\1{2,}/.test(password)) {
    score = Math.max(0, score - 0.5);
    suggestions.push('Avoid repeated characters (e.g., aaa, 111).');
  }

  if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwerty|asdf)/i.test(password)) {
    score = Math.max(0, score - 0.5);
    suggestions.push('Avoid sequential or keyboard-walk patterns (e.g., 123, qwerty).');
  }

  const finalScore = Math.min(5, Math.max(0, Math.round(score)));
  const labels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];

  return {
    score: finalScore,
    label: labels[finalScore],
    length,
    hasUpper,
    hasLower,
    hasDigit,
    hasSpecial,
    suggestions: suggestions.length ? suggestions : ['Password meets all local complexity and pattern checks.'],
  };
}

export async function queryBrowserPermissions() {
  const names = ['camera', 'microphone', 'geolocation', 'notifications', 'clipboard-read'];
  const result = {};

  if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
    for (const n of names) result[n] = 'unsupported';
    return result;
  }

  await Promise.all(
    names.map(async (name) => {
      try {
        const status = await navigator.permissions.query({ name });
        result[name] = status.state; // 'granted' | 'prompt' | 'denied'
      } catch {
        // Some browsers don't support querying clipboard-read or notifications via Permissions API
        if (name === 'notifications' && typeof Notification !== 'undefined') {
          result[name] = Notification.permission === 'default' ? 'prompt' : Notification.permission;
        } else {
          result[name] = 'unsupported';
        }
      }
    })
  );

  return result;
}

function inspectStorage(storageObj) {
  const keys = [];
  try {
    for (let i = 0; i < storageObj.length; i += 1) {
      const key = storageObj.key(i);
      const val = storageObj.getItem(key) || '';
      keys.push({
        key,
        bytes: new Blob([val]).size,
      });
    }
  } catch {
    // Storage access blocked by browser privacy mode
  }
  return keys;
}

export async function runBrowserPrivacyChecks(passwordSummary = null) {
  const httpsEnabled = window.location.protocol === 'https:';
  const isSecureContext = Boolean(window.isSecureContext);
  const origin = window.location.origin;

  // Same-origin non-HttpOnly cookie names only (never send cookie values)
  const rawCookies = document.cookie ? document.cookie.split(';').map((c) => c.trim()).filter(Boolean) : [];
  const cookieNames = rawCookies.map((c) => c.split('=')[0].trim()).filter(Boolean);

  const localStorageKeys = inspectStorage(window.localStorage);
  const sessionStorageKeys = inspectStorage(window.sessionStorage);

  // Check Performance API for third-party origins & mixed content
  const resources = performance.getEntriesByType('resource') || [];
  const thirdPartySet = new Set();
  let mixedContentCount = 0;

  for (const entry of resources) {
    try {
      const url = new URL(entry.name, origin);
      if (url.origin !== origin) {
        thirdPartySet.add(url.origin);
      }
      if (httpsEnabled && url.protocol === 'http:') {
        mixedContentCount += 1;
      }
    } catch {
      // ignore malformed resource URL
    }
  }

  const permissions = await queryBrowserPermissions();

  return {
    https_enabled: httpsEnabled,
    is_secure_context: isSecureContext,
    origin,
    dnt: navigator.doNotTrack || window.doNotTrack || null,
    cookies_enabled: Boolean(navigator.cookieEnabled),
    user_agent: navigator.userAgent || '',
    platform: navigator.platform || '',
    cookie_names: cookieNames,
    local_storage_keys: localStorageKeys,
    session_storage_keys: sessionStorageKeys,
    permissions,
    third_party_origins: Array.from(thirdPartySet),
    mixed_content_count: mixedContentCount,
    password_summary: passwordSummary || 'Not evaluated in this run',
  };
}
