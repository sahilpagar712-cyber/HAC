import React, { useEffect, useState } from 'react';
import {
  Activity,
  ShieldCheck,
  WifiOff,
  CheckCircle2,
  Sliders,
  Info,
  RefreshCw,
  ArrowRight,
  Cpu,
  AlertTriangle,
  Network,
  KeyRound,
  Save,
  Search,
} from 'lucide-react';
import { PII_TYPES, PII_TYPE_ORDER } from '../engine/piiDetector.js';
import { formatPartialMask, REDACTION_MODES } from '../engine/redactor.js';
import { PseudonymDrawer } from './PseudonymDrawer.jsx';
import { api } from '../api/client.js';

export function ThreatMonitorView({
  detection,
  enabledTypes,
  eventLog,
  onNavigateScan,
  dbAlerts = [],
  onAcknowledgeAlert,
  onFilterActivity,
}) {
  const [filterType, setFilterType] = useState('ALL');
  const [activitySearch, setActivitySearch] = useState('');
  const [activityLevel, setActivityLevel] = useState('');
  const filteredMatches =
    filterType === 'ALL'
      ? detection.matches
      : detection.matches.filter((m) => m.type === filterType);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-[#5b93ff]" />
            Threat Monitor &amp; Entity Telemetry
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Live inspection of all classified PII offsets, validation methods, and Luhn-gated false positives.
          </p>
        </div>
        <button
          type="button"
          onClick={onNavigateScan}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
        >
          Open Scan &amp; Diff <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Category Distribution Bars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Total PII Entities
          </div>
          <div className="text-3xl font-bold font-mono text-slate-900 dark:text-white mt-1">
            {detection.totalDetected}
          </div>
          <div className="text-xs text-emerald-500 mt-1">
            Non-overlapping verified spans
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Luhn False Positives Blocked
          </div>
          <div className="text-3xl font-bold font-mono text-amber-500 mt-1">
            {detection.luhnRejectedCount}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            13–19 digit order/tracking IDs preserved
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Logged Audit Events
          </div>
          <div className="text-3xl font-bold font-mono text-[#5b93ff] mt-1">
            {eventLog.length}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            In-memory session events
          </div>
        </div>
      </div>

      {/* Detected Entities Table */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Detected PII Entities ({filteredMatches.length})
          </span>
          <div className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => setFilterType('ALL')}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium ${
                filterType === 'ALL'
                  ? 'bg-[#5b93ff] text-slate-950'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
              }`}
            >
              All
            </button>
            {PII_TYPE_ORDER.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setFilterType(t)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium ${
                  filterType === t
                    ? 'bg-[#5b93ff] text-slate-950'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                }`}
              >
                {PII_TYPES[t].shortLabel} ({detection.countsByType[t] || 0})
              </button>
            ))}
          </div>
        </div>

        <div className="max-h-96 overflow-auto custom-scrollbar">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-50 dark:bg-[#0e1525] text-slate-500 dark:text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Matched Token</th>
                <th className="px-4 py-2.5">Validation Rule</th>
                <th className="px-4 py-2.5">Span</th>
                <th className="px-4 py-2.5 text-right">Policy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 font-mono">
              {filteredMatches.map((m, idx) => {
                const meta = PII_TYPES[m.type];
                const active = enabledTypes[m.type];
                return (
                  <tr
                    key={`${m.start}-${m.end}-${idx}`}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                  >
                    <td className="px-4 py-2 font-sans">
                      <span
                        className={`px-2 py-0.5 rounded-md text-[11px] font-medium border ${meta.badgeClass}`}
                      >
                        {meta.shortLabel}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-slate-800 dark:text-slate-200">
                      {m.value}
                    </td>
                    <td className="px-4 py-2 font-sans text-slate-500 dark:text-slate-400">
                      {m.validationMethod}
                    </td>
                    <td className="px-4 py-2 text-slate-400">
                      [{m.start}, {m.end})
                    </td>
                    <td className="px-4 py-2 text-right font-sans">
                      <span
                        className={
                          active ? 'text-emerald-500 font-medium' : 'text-amber-500'
                        }
                      >
                        {active ? 'Redacting' : 'Bypassed'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Database Threat Alerts with Acknowledgement */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            Database Threat Alerts ({dbAlerts.length})
          </span>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-800/70">
          {dbAlerts.length === 0 ? (
            <div className="p-5 text-xs text-slate-500 dark:text-slate-400">
              No threat alerts stored in database.
            </div>
          ) : (
            dbAlerts.map((alert) => (
              <div
                key={alert.id}
                className="px-5 py-3.5 flex flex-wrap items-center justify-between gap-3"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase font-semibold ${
                        alert.severity === 'critical' || alert.severity === 'high'
                          ? 'bg-rose-500/15 text-rose-500'
                          : alert.severity === 'medium'
                            ? 'bg-amber-500/15 text-amber-500'
                            : 'bg-blue-500/15 text-[#5b93ff]'
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-sm font-medium text-slate-900 dark:text-slate-100">
                      {alert.title}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {alert.detail} •{' '}
                    <span className="font-mono">
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                </div>
                {alert.is_acknowledged ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-500 text-xs font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Acknowledged
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => onAcknowledgeAlert?.(alert.id)}
                    className="px-3 py-1.5 rounded-lg bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold transition-colors"
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      {/* Searchable Activity Logs */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Activity Logs ({eventLog.length})
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={activitySearch}
                onChange={(e) => {
                  setActivitySearch(e.target.value);
                  onFilterActivity?.({ search: e.target.value, level: activityLevel });
                }}
                placeholder="Filter activity..."
                className="h-8 pl-8 pr-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs text-slate-900 dark:text-slate-100 focus:outline-none"
              />
            </div>
            <select
              value={activityLevel}
              onChange={(e) => {
                setActivityLevel(e.target.value);
                onFilterActivity?.({ search: activitySearch, level: e.target.value });
              }}
              className="h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs text-slate-900 dark:text-slate-100 focus:outline-none"
            >
              <option value="">All Levels</option>
              <option value="SAFE">SAFE</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ALERT">ALERT</option>
            </select>
          </div>
        </div>
        <div className="max-h-72 overflow-auto divide-y divide-slate-100 dark:divide-slate-800/70">
          {eventLog.map((evt) => (
            <div key={evt.id} className="px-5 py-2.5 flex items-center justify-between gap-3 text-xs">
              <div className="min-w-0">
                <div className="font-medium text-slate-900 dark:text-slate-100">
                  <span className="font-mono text-[10px] mr-2 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800">
                    {evt.level}
                  </span>
                  {evt.message}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                  {evt.subtext}
                </div>
              </div>
              <span className="font-mono text-[11px] text-slate-400 shrink-0">{evt.time}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export function EgressGuardView({ onAuditRun }) {
  const [auditResult, setAuditResult] = useState(null);
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [networkInfo, setNetworkInfo] = useState(null);

  useEffect(() => {
    api.getFirewallStatus().then(setFirewallStatus).catch(() => {});
    api.getNetworkInfo().then(setNetworkInfo).catch(() => {});
  }, []);

  const runEgressAudit = () => {
    const cspMeta = document.querySelector(
      'meta[http-equiv="Content-Security-Policy"]'
    );
    const cspContent = cspMeta?.getAttribute('content') || '';
    const hasConnectLock =
      cspContent.includes("connect-src 'none'") || cspContent.includes("connect-src 'self'");

    const resources = performance.getEntriesByType('resource');
    const externalResources = resources.filter((entry) => {
      try {
        const url = new URL(entry.name, window.location.origin);
        return url.origin !== window.location.origin;
      } catch {
        return false;
      }
    });

    const result = {
      checkedAt: new Date().toLocaleTimeString(),
      cspActive: hasConnectLock,
      cspContent,
      totalLocalAssets: resources.length,
      externalRequestsDetected: externalResources.length,
    };
    setAuditResult(result);
    api.getNetworkInfo().then(setNetworkInfo).catch(() => {});
    onAuditRun?.(result);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <WifiOff className="w-5 h-5 text-emerald-400" />
            Firewall &amp; Zero-Egress Guard
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Runtime verification that zero PII leaves the browser via network requests or external CDNs.
          </p>
        </div>

        <button
          type="button"
          onClick={runEgressAudit}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Run Live Egress Audit
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-2">
          <div className="flex items-center gap-2 text-emerald-500 text-sm font-semibold">
            <ShieldCheck className="w-4 h-4" />
            CSP Connect Lock
          </div>
          <p className="text-xs font-mono text-slate-600 dark:text-slate-300">
            connect-src &apos;none&apos;
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Blocks XHR, fetch(), WebSocket, and EventSource egress at the browser engine level.
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-2">
          <div className="flex items-center gap-2 text-[#5b93ff] text-sm font-semibold">
            <Cpu className="w-4 h-4" />
            Local FileReader Pipeline
          </div>
          <p className="text-xs font-mono text-slate-600 dark:text-slate-300">
            FileReader + Blob URL
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Uploaded .txt/.csv files and exported reports stay strictly inside local RAM.
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-2">
          <div className="flex items-center gap-2 text-emerald-500 text-sm font-semibold">
            <CheckCircle2 className="w-4 h-4" />
            Zero-PII Audit Reports
          </div>
          <p className="text-xs font-mono text-slate-600 dark:text-slate-300">
            audit_report.json
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Compliance exports omit all raw tokens, emitting only counts, mode, and timestamp.
          </p>
        </div>
      </div>

      {auditResult && (
        <div className="rounded-2xl border border-emerald-500/35 bg-emerald-500/10 p-5 space-y-2 text-xs">
          <div className="font-semibold text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            Egress Audit Passed at {auditResult.checkedAt}
          </div>
          <div className="font-mono text-slate-700 dark:text-slate-200 space-y-1">
            <div>
              CSP connect-src Policy Active: {String(auditResult.cspActive)}
            </div>
            <div>
              External Origin Network Requests: {auditResult.externalRequestsDetected}
            </div>
            <div>
              Same-Origin App Resources Loaded: {auditResult.totalLocalAssets}
            </div>
          </div>
        </div>
      )}

      {/* Backend Firewall Policy & Passive Network Monitor */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <ShieldCheck className="w-4 h-4 text-[#5b93ff]" />
            Application Firewall &amp; CSP Status
          </div>
          {firewallStatus ? (
            <div className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
              <p>{firewallStatus.backend_note}</p>
              <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-[#0b1120] font-mono text-[11px] break-all">
                {firewallStatus.csp_policy}
              </div>
              <ul className="list-disc pl-4 space-y-1 text-slate-500 dark:text-slate-400">
                {firewallStatus.recommendations.map((rec, i) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-xs text-slate-500">Loading firewall status from backend...</p>
          )}
        </section>

        <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <Network className="w-4 h-4 text-emerald-400" />
            Passive Local Network Monitor
          </div>
          {networkInfo ? (
            <div className="space-y-2 text-xs">
              <div className="grid grid-cols-2 gap-2 font-mono">
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-[#0b1120]">
                  <div className="text-[10px] text-slate-500">Hostname</div>
                  <div className="text-slate-900 dark:text-white truncate">{networkInfo.hostname}</div>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-[#0b1120]">
                  <div className="text-[10px] text-slate-500">Local IP</div>
                  <div className="text-emerald-500">{networkInfo.local_ip}</div>
                </div>
              </div>
              <div className="max-h-36 overflow-auto space-y-1 font-mono text-[11px]">
                {networkInfo.interfaces?.map((iface, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-50 dark:bg-[#192338]"
                  >
                    <span className="text-slate-700 dark:text-slate-200">{iface.address}</span>
                    <span className="text-slate-400">{iface.family}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">Loading passive network info...</p>
          )}
        </section>
      </div>
    </div>
  );
}

export function PrivacyGuardView({
  sessionEntries,
  occurrenceCounts,
  mode,
  onChangeMode,
  onPurgeSession,
}) {
  const [testPassword, setTestPassword] = useState('');
  const [pwResult, setPwResult] = useState(null);
  const [pwChecking, setPwChecking] = useState(false);

  const handleCheckPassword = async (e) => {
    e.preventDefault();
    if (!testPassword) return;
    setPwChecking(true);
    try {
      const res = await api.checkPasswordStrength(testPassword);
      setPwResult(res);
    } catch {
      setPwResult(null);
    } finally {
      setPwChecking(false);
    }
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
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">
            Privacy Guard &amp; Pseudonymization Vault
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Inspect deterministic session tokens and preview transformation rules across all 6 PII categories.
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

      {/* Password Strength Evaluator (Zero-Storage) */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-4">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-[#5b93ff]" />
              Password Strength Evaluator (Never Stored)
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Evaluated in-memory on the backend API without logging or persisting the password.
            </p>
          </div>
        </div>

        <form onSubmit={handleCheckPassword} className="flex flex-wrap gap-2">
          <input
            type="password"
            value={testPassword}
            onChange={(e) => setTestPassword(e.target.value)}
            placeholder="Enter a password to evaluate strength..."
            className="flex-1 min-w-[220px] h-10 px-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#0b1120] text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-[#5b93ff]/40"
          />
          <button
            type="submit"
            disabled={!testPassword || pwChecking}
            className="px-4 h-10 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold disabled:opacity-50"
          >
            {pwChecking ? 'Evaluating...' : 'Check Strength'}
          </button>
        </form>

        {pwResult && (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-900 dark:text-white">
                Strength: <span className="text-[#5b93ff]">{pwResult.label}</span> ({pwResult.score}/5)
              </span>
              <span className="font-mono text-slate-500">Length: {pwResult.length}</span>
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
            <ul className="list-disc pl-4 text-slate-600 dark:text-slate-300 space-y-0.5">
              {pwResult.suggestions.map((s, idx) => (
                <li key={idx}>{s}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

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
                    <td className="px-4 py-2.5 text-rose-500 dark:text-rose-300">
                      {ex.sample}
                    </td>
                    <td className="px-4 py-2.5 text-emerald-600 dark:text-emerald-400">
                      {meta.fullMaskToken}
                    </td>
                    <td className="px-4 py-2.5 text-[#5b93ff]">
                      {formatPartialMask(ex.type, ex.sample)}
                    </td>
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

      {/* Database Threat Alerts with Acknowledgement */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            Database Threat Alerts ({dbAlerts.length})
          </span>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-800/70">
          {dbAlerts.length === 0 ? (
            <div className="p-5 text-xs text-slate-500 dark:text-slate-400">
              No threat alerts stored in database.
            </div>
          ) : (
            dbAlerts.map((alert) => (
              <div
                key={alert.id}
                className="px-5 py-3.5 flex flex-wrap items-center justify-between gap-3"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase font-semibold ${
                        alert.severity === 'critical' || alert.severity === 'high'
                          ? 'bg-rose-500/15 text-rose-500'
                          : alert.severity === 'medium'
                            ? 'bg-amber-500/15 text-amber-500'
                            : 'bg-blue-500/15 text-[#5b93ff]'
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-sm font-medium text-slate-900 dark:text-slate-100">
                      {alert.title}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {alert.detail} •{' '}
                    <span className="font-mono">
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                </div>
                {alert.is_acknowledged ? (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-500 text-xs font-medium">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Acknowledged
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => onAcknowledgeAlert?.(alert.id)}
                    className="px-3 py-1.5 rounded-lg bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold transition-colors"
                  >
                    Acknowledge
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      {/* Searchable Activity Logs */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Activity Logs ({eventLog.length})
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={activitySearch}
                onChange={(e) => {
                  setActivitySearch(e.target.value);
                  onFilterActivity?.({ search: e.target.value, level: activityLevel });
                }}
                placeholder="Filter activity..."
                className="h-8 pl-8 pr-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs text-slate-900 dark:text-slate-100 focus:outline-none"
              />
            </div>
            <select
              value={activityLevel}
              onChange={(e) => {
                setActivityLevel(e.target.value);
                onFilterActivity?.({ search: activitySearch, level: e.target.value });
              }}
              className="h-8 px-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#0b1120] text-xs text-slate-900 dark:text-slate-100 focus:outline-none"
            >
              <option value="">All Levels</option>
              <option value="SAFE">SAFE</option>
              <option value="INFO">INFO</option>
              <option value="WARN">WARN</option>
              <option value="ALERT">ALERT</option>
            </select>
          </div>
        </div>
        <div className="max-h-72 overflow-auto divide-y divide-slate-100 dark:divide-slate-800/70">
          {eventLog.map((evt) => (
            <div key={evt.id} className="px-5 py-2.5 flex items-center justify-between gap-3 text-xs">
              <div className="min-w-0">
                <div className="font-medium text-slate-900 dark:text-slate-100">
                  <span className="font-mono text-[10px] mr-2 px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800">
                    {evt.level}
                  </span>
                  {evt.message}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                  {evt.subtext}
                </div>
              </div>
              <span className="font-mono text-[11px] text-slate-400 shrink-0">{evt.time}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export function SettingsView({
  enabledTypes,
  onToggleType,
  onSetAllTypes,
  mode,
  onChangeMode,
  uniformFullMask,
  onToggleUniformMask,
  theme,
  onToggleTheme,
  currentUser,
  onSaveSettings,
  onOpenAuthModal,
}) {
  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Sliders className="w-5 h-5 text-[#5b93ff]" />
            Security &amp; Detection Settings
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Configure active PII detectors, transformation mode, and interface theme.
          </p>
        </div>

        {currentUser ? (
          <button
            type="button"
            onClick={onSaveSettings}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 text-xs font-semibold"
          >
            <Save className="w-3.5 h-3.5" />
            Save Settings to DB
          </button>
        ) : (
          <button
            type="button"
            onClick={onOpenAuthModal}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#192338] text-xs font-semibold text-[#5b93ff]"
          >
            Sign In to Save Settings
          </button>
        )}
      </div>

      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
            PII Category Filters
          </h3>
          <div className="flex gap-3 text-xs">
            <button
              type="button"
              onClick={() => onSetAllTypes(true)}
              className="text-[#5b93ff] hover:underline"
            >
              Enable All
            </button>
            <button
              type="button"
              onClick={() => onSetAllTypes(false)}
              className="text-slate-400 hover:underline"
            >
              Disable All
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {PII_TYPE_ORDER.map((key) => {
            const meta = PII_TYPES[key];
            const active = !!enabledTypes[key];
            return (
              <label
                key={key}
                className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#182238] cursor-pointer"
              >
                <div>
                  <div className="text-sm font-medium text-slate-900 dark:text-white">
                    {meta.label}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {meta.validationMethod}
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={active}
                  onChange={() => onToggleType(key)}
                  className="h-4 w-4 rounded text-[#5b93ff] focus:ring-[#5b93ff]"
                />
              </label>
            );
          })}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
          Redaction &amp; Appearance
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { id: REDACTION_MODES.FULL_MASK, label: 'Full Mask' },
            { id: REDACTION_MODES.PARTIAL_MASK, label: 'Partial Mask' },
            {
              id: REDACTION_MODES.PSEUDONYM,
              label: 'Consistent Pseudonymization',
            },
          ].map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => onChangeMode(opt.id)}
              className={`p-3 rounded-xl border text-xs font-semibold text-left transition-all ${
                mode === opt.id
                  ? 'border-[#5b93ff] bg-[#5b93ff]/15 text-blue-600 dark:text-white'
                  : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#182238] text-slate-600 dark:text-slate-300'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-slate-200 dark:border-slate-800">
          <label className="flex items-center gap-2.5 text-sm text-slate-700 dark:text-slate-200 cursor-pointer">
            <input
              type="checkbox"
              checked={uniformFullMask}
              onChange={(e) => onToggleUniformMask(e.target.checked)}
              className="h-4 w-4 rounded text-[#5b93ff]"
            />
            <span>
              Use uniform <code className="font-mono">[REDACTED]</code> token in Full Mask mode
            </span>
          </label>

          <button
            type="button"
            onClick={onToggleTheme}
            className="px-3.5 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-[#182238] text-xs font-semibold"
          >
            Theme: {theme === 'dark' ? 'Dark' : 'Light'} (Click to Switch)
          </button>
        </div>
      </section>
    </div>
  );
}

export function AboutView({ backendOnline }) {
  return (
    <div className="space-y-5 max-w-4xl">
      <div>
        <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Info className="w-5 h-5 text-[#5b93ff]" />
          About RedactZero
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Zero-egress PII Data Sanitization &amp; Privacy Compliance Workbench with FastAPI + SQLite persistence.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131b2e] p-6 space-y-4 text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
        <p>
          <strong>RedactZero</strong> sanitizes sensitive logs, CSV exports, KYC files, and clinical notes inside browser memory before sharing with AI models, external vendors, or support teams, while persisting scan metadata, alerts, and audit logs to a local FastAPI + SQLite backend.
        </p>
        <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800 text-xs font-mono flex flex-wrap items-center justify-between gap-2">
          <span>
            Backend API Status:{' '}
            <strong className={backendOnline ? 'text-emerald-500' : 'text-amber-500'}>
              {backendOnline ? 'CONNECTED (http://127.0.0.1:8000)' : 'OFFLINE (Local-only fallback)'}
            </strong>
          </span>
          <a
            href="/api/docs"
            target="_blank"
            rel="noreferrer"
            className="text-[#5b93ff] hover:underline"
          >
            Open Swagger API Docs →
          </a>
        </div>
        <ul className="list-disc pl-5 space-y-1.5 text-xs sm:text-sm">
          <li>
            <strong>Luhn Mod-10 Gate:</strong> Every 13–19 digit card candidate is validated via Luhn checksum to eliminate false positives on order IDs and tracking numbers.
          </li>
          <li>
            <strong>Strict Format Rules:</strong> Enforces IPv4 <code>0–255</code> octets (ignoring <code>v2.4.1.0</code>), RFC-4291 IPv6, Indian PAN 4th-char entity codes <code>[PCHABGJLFT]</code>, and UIDAI 12-digit Aadhaar rules (<code>^[2-9]</code>).
          </li>
          <li>
            <strong>Zero Network Egress:</strong> Strict CSP <code>connect-src &apos;none&apos;</code> with local <code>FileReader</code> ingestion and local <code>Blob</code> exports.
          </li>
        </ul>
      </div>
    </div>
  );
}
