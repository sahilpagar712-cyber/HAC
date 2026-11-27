import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Lock,
  Globe,
  Cookie,
  Database,
  KeyRound,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Eye,
  EyeOff,
  Camera,
  Mic,
  MapPin,
  Bell,
  Clipboard,
  Loader2,
  Info,
} from 'lucide-react';
import { PII_TYPES } from '../engine/piiDetector.js';
import { formatPartialMask, REDACTION_MODES } from '../engine/redactor.js';
import { PseudonymDrawer } from './PseudonymDrawer.jsx';
import { api } from '../api/client.js';
import {
  evaluatePasswordLocally,
  queryBrowserPermissions,
  runBrowserPrivacyChecks,
} from '../utils/privacyScanner.js';

export function PrivacyGuardView({
  sessionEntries,
  occurrenceCounts,
  mode,
  onChangeMode,
  onPurgeSession,
  onNotify,
}) {
  const [dashboard, setDashboard] = useState(null);
  const [latestReport, setLatestReport] = useState(null);
  const [history, setHistory] = useState([]);
  const [permissions, setPermissions] = useState({});
  const [checking, setChecking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Local password checker state (never sent to backend)
  const [localPassword, setLocalPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const pwResult = evaluatePasswordLocally(localPassword);

  // Privacy settings
  const [privSettings, setPrivSettings] = useState({
    auto_flag_sensitive_storage: true,
    check_third_party_resources: true,
    warn_on_http: true,
    prefer_session_over_local: true,
  });

  const loadDashboard = async () => {
    setLoading(true);
    setError('');
    try {
      const [dash, perms] = await Promise.all([
        api.getPrivacyDashboard(),
        queryBrowserPermissions(),
      ]);
      setDashboard(dash);
      setLatestReport(dash.latest_report);
      setHistory(dash.recent_checks || []);
      if (dash.settings) setPrivSettings(dash.settings);
      setPermissions(perms);
    } catch (err) {
      setError(err.message || 'Failed to load Privacy Guard dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const handleRunPrivacyCheck = async () => {
    if (checking) return;
    setChecking(true);
    setError('');
    try {
      const pwSummary = pwResult
        ? `Evaluated locally: ${pwResult.label} (${pwResult.score}/5, length ${pwResult.length})`
        : 'Not evaluated';
      const telemetry = await runBrowserPrivacyChecks(pwSummary);
      const saved = await api.runPrivacyCheck(telemetry);
      setLatestReport(saved);
      setPermissions(telemetry.permissions);
      await loadDashboard();
      onNotify?.(`Privacy check completed: ${saved.overall_score}/100 (${saved.risk_level})`);
    } catch (err) {
      setError(err.message || 'Privacy check failed');
    } finally {
      setChecking(false);
    }
  };

  const handleRefreshPermissions = async () => {
    const perms = await queryBrowserPermissions();
    setPermissions(perms);
    onNotify?.('Refreshed browser permission states via Permissions API');
  };

  const handleRequestNotificationsOnly = async () => {
    if (typeof Notification === 'undefined') {
      onNotify?.('Notifications API is not supported in this browser');
      return;
    }
    try {
      await Notification.requestPermission();
      const perms = await queryBrowserPermissions();
      setPermissions(perms);
      onNotify?.(`Notification permission: ${Notification.permission}`);
    } catch {
      onNotify?.('Could not request notification permission');
    }
  };

  const handleToggleSetting = async (key) => {
    const updated = { ...privSettings, [key]: !privSettings[key] };
    setPrivSettings(updated);
    try {
      await api.savePrivacySettings(updated);
      onNotify?.('Privacy Guard settings saved');
    } catch (err) {
      onNotify?.(err.message || 'Failed to save privacy settings');
    }
  };

  const handleDownloadPdf = async (reportId) => {
    try {
      const blob = await api.downloadPrivacyReportPdf(reportId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securex_privacy_report_${reportId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      onNotify?.(`Downloaded Privacy Report #${reportId}`);
    } catch (err) {
      onNotify?.(err.message || 'Failed to download PDF report');
    }
  };

  const permCards = [
    { key: 'camera', label: 'Camera', icon: Camera },
    { key: 'microphone', label: 'Microphone', icon: Mic },
    { key: 'geolocation', label: 'Location', icon: MapPin },
    { key: 'notifications', label: 'Notifications', icon: Bell },
    { key: 'clipboard-read', label: 'Clipboard', icon: Clipboard },
  ];

  const permBadge = (state) => {
    if (state === 'granted') return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
    if (state === 'denied') return 'bg-rose-500/15 text-rose-500 border-rose-500/30';
    if (state === 'prompt') return 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30';
    return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  };

  const examples = [
    { type: 'EMAIL', sample: 'priya.sharma@novacloud.io' },
    { type: 'PHONE', sample: '+91 98765 43210' },
    { type: 'IP_ADDRESS', sample: '192.168.14.205' },
    { type: 'PAN', sample: 'ABCPM1234K' },
    { type: 'AADHAAR', sample: '2345 6789 0123' },
    { type: 'CREDIT_CARD', sample: '4532-0151-1283-0366' },
  ];

  return (
    <div className="space-y-5">
      {/* Header + Check Privacy Action */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-[#5b93ff]" />
            Privacy Guard &amp; Browser Posture
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Inspect HTTPS, same-origin cookies, local/session storage, browser permissions, and evaluate passwords 100% locally.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleRunPrivacyCheck}
            disabled={checking}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold disabled:opacity-60"
          >
            {checking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            {checking ? 'Checking Privacy...' : 'Check Privacy'}
          </button>

          {latestReport && (
            <button
              type="button"
              onClick={() => handleDownloadPdf(latestReport.id)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#131b2e] text-xs font-semibold hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <Download className="w-3.5 h-3.5 text-[#5b93ff]" />
              Export PDF Report
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-500 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Privacy Dashboard Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Overall Privacy Score</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
              {latestReport ? `${latestReport.overall_score}/100` : '—'}
            </span>
            {latestReport && (
              <span
                className={`text-[11px] font-bold ${
                  latestReport.risk_level === 'GOOD'
                    ? 'text-emerald-500'
                    : latestReport.risk_level === 'MODERATE'
                      ? 'text-amber-500'
                      : 'text-rose-500'
                }`}
              >
                {latestReport.risk_level}
              </span>
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {dashboard ? `${dashboard.total_checks} check(s) recorded` : loading ? 'Loading...' : 'Run Check Privacy'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-[#5b93ff]" />
            HTTPS &amp; Transport
          </div>
          <div className="text-lg font-bold mt-1 text-slate-900 dark:text-white">
            {window.location.protocol === 'https:' ? 'HTTPS Active' : 'HTTP (Localhost)'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Secure Context: {String(Boolean(window.isSecureContext))} • DNT: {navigator.doNotTrack || 'unset'}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
            <Cookie className="w-3.5 h-3.5 text-amber-500" />
            Same-Origin Cookies
          </div>
          <div className="text-lg font-bold font-mono mt-1 text-slate-900 dark:text-white">
            {latestReport ? latestReport.cookie_summary_json?.accessible_count ?? 0 : 0} accessible
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            HttpOnly &amp; third-party cookies hidden by SOP
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-emerald-500" />
            Browser Storage
          </div>
          <div className="text-lg font-bold font-mono mt-1 text-slate-900 dark:text-white">
            {latestReport
              ? `${latestReport.storage_summary_json?.local_storage_count ?? 0} local / ${latestReport.storage_summary_json?.session_storage_count ?? 0} session`
              : `${window.localStorage.length} local / ${window.sessionStorage.length} session`}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            External Origins: {latestReport?.third_party_indicators_json?.external_origins_count ?? 0}
          </div>
        </div>
      </div>

      {/* Permission Monitor + Local Password Checker */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Permission Monitor */}
        <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Browser Permission Monitor
              </h3>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Read-only status via Permissions API (never requests camera, mic, or location automatically).
              </p>
            </div>
            <button
              type="button"
              onClick={handleRefreshPermissions}
              className="p-2 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
              title="Refresh permission states"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2">
            {permCards.map((p) => {
              const Icon = p.icon;
              const state = permissions[p.key] || 'unknown';
              return (
                <div
                  key={p.key}
                  className="flex items-center justify-between px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 text-xs"
                >
                  <span className="flex items-center gap-2 font-medium text-slate-800 dark:text-slate-200">
                    <Icon className="w-4 h-4 text-[#5b93ff]" />
                    {p.label}
                  </span>
                  <div className="flex items-center gap-2">
                    {p.key === 'notifications' && state === 'prompt' && (
                      <button
                        type="button"
                        onClick={handleRequestNotificationsOnly}
                        className="text-[11px] text-[#5b93ff] hover:underline"
                      >
                        Test Prompt
                      </button>
                    )}
                    <span className={`px-2 py-0.5 rounded-md border font-mono text-[11px] ${permBadge(state)}`}>
                      {state}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Local Password Strength Evaluator */}
        <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-[#5b93ff]" />
              Local Password Privacy Check
            </h3>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Evaluated 100% locally in browser memory — never sent to the backend, stored in SQLite, or logged.
            </p>
          </div>

          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={localPassword}
              onChange={(e) => setLocalPassword(e.target.value)}
              placeholder="Type a password to evaluate locally..."
              className="w-full h-10 pl-3.5 pr-10 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#0b1120] text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#5b93ff]/40"
            />
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              aria-label="Toggle password visibility"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          {pwResult ? (
            <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold">
                  Strength: <span className="text-[#5b93ff]">{pwResult.label}</span> ({pwResult.score}/5)
                </span>
                <span className="font-mono text-slate-400">Length: {pwResult.length}</span>
              </div>
              <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                <div
                  className={`h-full transition-all ${
                    pwResult.score >= 4
                      ? 'bg-emerald-500'
                      : pwResult.score >= 2
                        ? 'bg-amber-500'
                        : 'bg-rose-500'
                  }`}
                  style={{ width: `${(pwResult.score / 5) * 100}%` }}
                />
              </div>
              <ul className="list-disc pl-4 space-y-0.5 text-slate-600 dark:text-slate-300">
                {pwResult.suggestions.map((s, idx) => (
                  <li key={idx}>{s}</li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="p-3.5 rounded-xl bg-slate-50/70 dark:bg-[#0b1120]/60 border border-dashed border-slate-300 dark:border-slate-800 text-xs text-slate-500">
              Start typing above to check length, character variety, dictionary matches, and sequential patterns locally.
            </div>
          )}
        </section>
      </div>

      {/* Recommendations + Cookie & Storage Inspection */}
      {latestReport && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              Privacy Recommendations ({(latestReport.recommendations_json || []).length})
            </h3>
            <div className="space-y-2.5 max-h-72 overflow-auto">
              {(latestReport.recommendations_json || []).map((rec, i) => (
                <div
                  key={i}
                  className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                      {rec.severity === 'high' || rec.severity === 'medium' ? (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                      )}
                      {rec.title}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800">
                      {rec.status}
                    </span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-400">{rec.why_it_matters}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              Same-Origin Cookie &amp; Storage Analysis
            </h3>
            <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/25 text-[11px] text-blue-700 dark:text-blue-300 flex items-start gap-2">
              <Info className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{latestReport.cookie_summary_json?.limitation_note}</span>
            </div>
            <div className="space-y-2 text-xs">
              <div className="font-semibold text-slate-700 dark:text-slate-300">
                localStorage Keys ({latestReport.storage_summary_json?.local_storage_count ?? 0})
              </div>
              <div className="max-h-32 overflow-auto space-y-1 font-mono text-[11px]">
                {(latestReport.storage_summary_json?.local_storage_keys || []).map((k, idx) => {
                  const flagged = (latestReport.storage_summary_json?.flagged_sensitive_keys || []).includes(k.key);
                  return (
                    <div
                      key={idx}
                      className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-50 dark:bg-[#0b1120]"
                    >
                      <span className={flagged ? 'text-amber-500 font-semibold' : 'text-slate-700 dark:text-slate-200'}>
                        {k.key} {flagged ? '(Review)' : ''}
                      </span>
                      <span className="text-slate-400">{k.bytes} B</span>
                    </div>
                  );
                })}
                {(latestReport.storage_summary_json?.local_storage_keys || []).length === 0 && (
                  <div className="text-slate-500">No localStorage keys present.</div>
                )}
              </div>
            </div>
          </section>
        </div>
      )}

      {/* Privacy Settings + Recent Privacy Checks */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
            Privacy Guard Preferences
          </h3>
          {[
            { key: 'auto_flag_sensitive_storage', label: 'Flag sensitive-looking localStorage keys' },
            { key: 'check_third_party_resources', label: 'Inspect third-party resource origins' },
            { key: 'warn_on_http', label: 'Warn when not using HTTPS' },
            { key: 'prefer_session_over_local', label: 'Recommend sessionStorage over localStorage' },
          ].map((opt) => (
            <label
              key={opt.key}
              className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 text-xs cursor-pointer"
            >
              <span>{opt.label}</span>
              <input
                type="checkbox"
                checked={Boolean(privSettings[opt.key])}
                onChange={() => handleToggleSetting(opt.key)}
                className="h-4 w-4 rounded text-[#5b93ff]"
              />
            </label>
          ))}
        </section>

        <section className="lg:col-span-7 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
            Recent Privacy Checks ({history.length})
          </h3>
          {history.length === 0 ? (
            <p className="text-xs text-slate-500">No privacy checks stored yet. Click &ldquo;Check Privacy&rdquo; above.</p>
          ) : (
            <div className="space-y-2 max-h-56 overflow-auto">
              {history.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 text-xs"
                >
                  <div>
                    <div className="font-semibold text-slate-900 dark:text-white">
                      Score: {item.overall_score}/100 ({item.risk_level})
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {new Date(item.created_at).toLocaleString()} • {item.origin}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleDownloadPdf(item.id)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#5b93ff]/15 text-[#5b93ff] hover:bg-[#5b93ff]/25 font-medium"
                  >
                    <Download className="w-3 h-3" /> PDF
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Existing Pseudonym Vault & Redaction Policy Matrix */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white">
            Pseudonymization Vault &amp; Redaction Policy Matrix
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Inspect deterministic session tokens and transformation rules across all 6 PII categories.
          </p>
        </div>
        {mode !== REDACTION_MODES.PSEUDONYM && (
          <button
            type="button"
            onClick={() => onChangeMode(REDACTION_MODES.PSEUDONYM)}
            className="px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
          >
            Activate Consistent Pseudonymization
          </button>
        )}
      </div>

      <PseudonymDrawer
        entries={sessionEntries}
        occurrenceCounts={occurrenceCounts}
        isPseudonymMode={true}
        onPurgeSession={onPurgeSession}
      />

      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 text-sm font-semibold text-slate-900 dark:text-white">
          Redaction Policy Reference Matrix
        </div>
        <div className="overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-[#0e1525] text-slate-500 dark:text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Synthetic Example</th>
                <th className="px-4 py-2.5">Full Mask</th>
                <th className="px-4 py-2.5">Partial Mask</th>
                <th className="px-4 py-2.5">Pseudonym</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 font-mono">
              {examples.map((ex, idx) => {
                const meta = PII_TYPES[ex.type];
                return (
                  <tr key={ex.type}>
                    <td className="px-4 py-2.5 font-sans font-medium text-slate-800 dark:text-slate-200">
                      {meta.label}
                    </td>
                    <td className="px-4 py-2.5 text-rose-500 dark:text-rose-300">{ex.sample}</td>
                    <td className="px-4 py-2.5 text-emerald-600 dark:text-emerald-400">{meta.fullMaskToken}</td>
                    <td className="px-4 py-2.5 text-[#5b93ff]">{formatPartialMask(ex.type, ex.sample)}</td>
                    <td className="px-4 py-2.5 text-cyan-500">
                      {meta.prefix}_0{(idx % 2) + 1}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
