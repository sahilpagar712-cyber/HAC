/**
 * Centralized API client for RedactZero FastAPI backend.
 * Uses VITE_API_URL (default '/api' via Vite proxy) and manages JWT bearer tokens.
 */

const API_BASE = import.meta.env.VITE_API_URL || '/api';
const TOKEN_KEY = 'redactzero_auth_token';
const USER_KEY = 'redactzero_auth_user';

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setAuthSession(token, user) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  }
  if (user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
}

export function clearAuthSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function request(path, options = {}) {
  const token = getStoredToken();
  const headers = {
    ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {}),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const err = await response.json();
      if (err.detail) {
        message = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
      }
    } catch {
      // ignore non-JSON error
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) return null;
  return response.json();
}

export const api = {
  // Health
  health: () => request('/health'),

  // Auth
  register: (payload) =>
    request('/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  logout: () => request('/auth/logout', { method: 'POST' }),
  me: () => request('/auth/me'),

  // Dashboard
  getDashboardStats: () => request('/dashboard/stats'),

  // Scans
  createScan: (payload) =>
    request('/scans/', { method: 'POST', body: JSON.stringify(payload) }),
  uploadFileScan: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/scans/upload', { method: 'POST', body: formData });
  },
  listScans: (limit = 20) => request(`/scans/?limit=${limit}`),

  // Alerts
  listAlerts: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.severity) qs.set('severity', params.severity);
    if (params.acknowledged !== undefined) qs.set('acknowledged', String(params.acknowledged));
    const query = qs.toString();
    return request(`/alerts/${query ? `?${query}` : ''}`);
  },
  acknowledgeAlert: (alertId) =>
    request(`/alerts/${alertId}/acknowledge`, { method: 'PATCH' }),

  // Activity
  listActivity: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.level) qs.set('level', params.level);
    if (params.search) qs.set('search', params.search);
    if (params.limit) qs.set('limit', String(params.limit));
    const query = qs.toString();
    return request(`/activity/${query ? `?${query}` : ''}`);
  },
  createActivity: (payload) =>
    request('/activity/', { method: 'POST', body: JSON.stringify(payload) }),

  // Settings
  getSettings: () => request('/settings/'),
  saveSettings: (settings) =>
    request('/settings/', { method: 'PUT', body: JSON.stringify({ settings }) }),

  // Firewall & Network & Privacy
  getFirewallStatus: () => request('/firewall/status'),
  getNetworkInfo: () => request('/network/info'),
  // Privacy Guard
  getPrivacyDashboard: () => request('/privacy/dashboard'),
  runPrivacyCheck: (payload) =>
    request('/privacy/check', { method: 'POST', body: JSON.stringify(payload) }),
  listPrivacyHistory: () => request('/privacy/history'),
  getPrivacyRecommendations: () => request('/privacy/recommendations'),
  savePrivacySettings: (settings) =>
    request('/privacy/settings', { method: 'POST', body: JSON.stringify(settings) }),
  downloadPrivacyReportPdf: async (reportId) => {
    const token = getStoredToken();
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await fetch(`${API_BASE}/privacy/report/${reportId}`, { headers });
    if (!res.ok) throw new Error('Failed to download privacy PDF report');
    return res.blob();
  },

  // Image Security Scanner
  uploadImageForScan: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/image-scanner/upload', { method: 'POST', body: formData });
  },
  scanUploadedImage: (uploadId) => {
    const formData = new FormData();
    formData.append('upload_id', uploadId);
    return request('/image-scanner/scan', { method: 'POST', body: formData });
  },
  listImageScans: (params = {}) => {
    const qs = new URLSearchParams();
    if (params.search) qs.set('search', params.search);
    if (params.risk_category) qs.set('risk_category', params.risk_category);
    if (params.date_from) qs.set('date_from', params.date_from);
    if (params.date_to) qs.set('date_to', params.date_to);
    const query = qs.toString();
    return request(`/image-scanner/history${query ? `?${query}` : ''}`);
  },
  getImageScanDetail: (scanId) => request(`/image-scanner/history/${scanId}`),
  deleteImageScan: (scanId) =>
    request(`/image-scanner/history/${scanId}`, { method: 'DELETE' }),
  downloadImageReportPdf: async (scanId) => {
    const token = getStoredToken();
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await fetch(`${API_BASE}/image-scanner/report/${scanId}`, { headers });
    if (!res.ok) throw new Error('Failed to download PDF report');
    return res.blob();
  },
};
