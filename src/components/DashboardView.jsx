import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  AlertCircle,
  Clock,
  Wrench,
  Search,
  Shield,
  Lock,
  Settings,
  ArrowRight,
  Loader2,
} from 'lucide-react';
import { SAMPLE_DATASETS } from '../data/sampleDatasets.js';

export function DashboardView({
  inputText,
  sourceMeta,
  detection,
  activeMatches,
  modeLabel,
  isScanning,
  scanProgress,
  onRunQuickScan,
  onLoadSample,
  onNavigate,
  alerts,
  eventLog,
  dashboardStats,
}) {
  const totalDetected = detection.totalDetected;
  const activeCount = activeMatches.length;
  const unmaskedCount = Math.max(0, totalDetected - activeCount);
  const isCleanOrProtected = inputText.length === 0 || unmaskedCount === 0;

  return (
    <div className="space-y-5">
      {/* Top Row: Hero Status Card + Threat Alerts */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Hero Card */}
        <section className="xl:col-span-8 relative overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-gradient-to-br from-slate-100 via-white to-blue-50 dark:from-[#0f243f] dark:via-[#101c32] dark:to-[#111827] p-6 sm:p-8 flex flex-col justify-between min-h-[260px] shadow-sm">
          {/* Subtle decorative wave lines */}
          <svg
            aria-hidden="true"
            viewBox="0 0 800 300"
            className="pointer-events-none absolute inset-0 w-full h-full opacity-40 dark:opacity-30"
            preserveAspectRatio="none"
          >
            <path
              d="M0,260 C180,180 340,290 520,210 C650,150 730,190 800,130"
              fill="none"
              stroke="#3b82f6"
              strokeWidth="1"
              strokeOpacity="0.35"
            />
            <path
              d="M0,280 C200,200 360,310 540,230 C670,170 740,210 800,155"
              fill="none"
              stroke="#10b981"
              strokeWidth="1"
              strokeOpacity="0.25"
            />
            <path
              d="M0,240 C160,165 320,270 500,195 C640,135 720,175 800,110"
              fill="none"
              stroke="#60a5fa"
              strokeWidth="0.8"
              strokeOpacity="0.25"
            />
          </svg>

          <div className="relative z-10 flex flex-col sm:flex-row items-start sm:items-center gap-6 my-auto">
            {/* Large Shield Icon */}
            <div className="relative shrink-0 flex items-center justify-center">
              <div
                className={`w-24 h-24 sm:w-28 sm:h-28 rounded-3xl flex items-center justify-center ${
                  isCleanOrProtected
                    ? 'bg-emerald-500/10 border border-emerald-500/25 shadow-[0_0_40px_rgba(16,185,129,0.2)]'
                    : 'bg-amber-500/10 border border-amber-500/30 shadow-[0_0_40px_rgba(245,158,11,0.2)]'
                }`}
              >
                {isCleanOrProtected ? (
                  <ShieldCheck className="w-14 h-14 text-emerald-500 dark:text-[#2dd488]" />
                ) : (
                  <ShieldAlert className="w-14 h-14 text-amber-500" />
                )}
              </div>
            </div>

            {/* Hero Copy & Primary Action */}
            <div className="space-y-3 min-w-0 flex-1">
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
                {inputText.length === 0 ? (
                  <>
                    Your workspace is{' '}
                    <span className="text-emerald-600 dark:text-[#2dd488]">
                      secure!
                    </span>
                  </>
                ) : isCleanOrProtected ? (
                  <>
                    Your data is{' '}
                    <span className="text-emerald-600 dark:text-[#2dd488]">
                      protected!
                    </span>
                  </>
                ) : (
                  <>
                    <span className="text-amber-500">{unmaskedCount}</span> PII{' '}
                    {unmaskedCount === 1 ? 'entity' : 'entities'} unmasked!
                  </>
                )}
              </h2>

              <p className="text-sm text-slate-600 dark:text-slate-300 max-w-xl">
                {inputText.length === 0
                  ? 'No exposed PII in memory. Load a sample dataset or paste sensitive logs to inspect.'
                  : `${activeCount} of ${totalDetected} detected PII entities sanitized via ${modeLabel} • ${detection.luhnRejectedCount} non-Luhn decoys ignored.`}
              </p>

              {/* Progress bar when Quick Scan runs */}
              {isScanning && (
                <div className="max-w-sm space-y-1">
                  <div className="flex justify-between text-[11px] font-mono text-blue-500 dark:text-[#5b93ff]">
                    <span>Running local regex + Luhn pass...</span>
                    <span>{scanProgress}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-[#5b93ff] transition-all duration-150"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>
              )}

              <div className="flex flex-wrap items-center gap-3 pt-1">
                <button
                  type="button"
                  onClick={onRunQuickScan}
                  disabled={isScanning}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full bg-[#5b93ff] hover:bg-[#4a83f2] text-slate-950 font-semibold text-sm shadow-lg shadow-blue-500/25 disabled:opacity-70 transition-all"
                >
                  {isScanning ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4 fill-current" />
                  )}
                  <span>{isScanning ? 'Scanning...' : 'Run Quick Scan'}</span>
                </button>

                <button
                  type="button"
                  onClick={() => onNavigate('scan')}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full border border-slate-300 dark:border-slate-700 bg-white/70 dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-semibold transition-colors"
                >
                  <span>Open Diff Workbench</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Quick Sample Switcher Footer */}
          <div className="relative z-10 mt-5 pt-3.5 border-t border-slate-200/70 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="text-slate-500 dark:text-slate-400">
              Active Buffer:{' '}
              <strong className="font-mono text-slate-800 dark:text-slate-200">
                {sourceMeta?.fileName || 'manual_paste.txt'}
              </strong>
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              {SAMPLE_DATASETS.map((sample) => {
                const active = sourceMeta?.sampleId === sample.id;
                return (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => onLoadSample(sample)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-medium transition-colors ${
                      active
                        ? 'bg-blue-500/20 text-blue-600 dark:text-[#7aa7ff] border border-blue-500/35'
                        : 'bg-slate-200/70 dark:bg-slate-800/70 text-slate-600 dark:text-slate-300 hover:text-white'
                    }`}
                  >
                    {sample.shortLabel}
                  </button>
                );
              })}
            </div>
          </div>
        </section>

        {/* Threat Alerts Card */}
        <section className="xl:col-span-4 rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 flex flex-col justify-between shadow-sm">
          <div>
            <div className="flex items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-full bg-rose-500/15 flex items-center justify-center">
                  <AlertCircle className="w-4 h-4 text-rose-500" />
                </div>
                <h3 className="text-base font-semibold text-slate-900 dark:text-white">
                  Threat Alerts
                </h3>
              </div>

              <button
                type="button"
                onClick={() => onNavigate('monitor')}
                className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 dark:text-[#5b93ff] hover:underline"
              >
                View All <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-3">
              {alerts.map((alert) => {
                const dotClass = {
                  red: 'bg-rose-500',
                  blue: 'bg-[#5b93ff]',
                  green: 'bg-emerald-400',
                  amber: 'bg-amber-400',
                }[alert.tone || 'blue'];

                return (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => onNavigate(alert.targetTab || 'monitor')}
                    className="w-full text-left flex items-start justify-between gap-3 p-2.5 -mx-2 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <span
                        className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${dotClass}`}
                      />
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">
                          {alert.title}
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-400 truncate">
                          {alert.detail}
                        </div>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400 shrink-0 mt-0.5">
                      {alert.time}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </section>
      </div>

      {/* Bottom Row: Recent Activity + Quick Tools */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        {/* Recent Activity Card */}
        <section className="xl:col-span-6 rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm">
          <div className="flex items-center justify-between gap-2 mb-4">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center">
                <Clock className="w-4 h-4 text-slate-500 dark:text-slate-300" />
              </div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-white">
                Recent Activity
              </h3>
            </div>

            <button
              type="button"
              onClick={() => onNavigate('monitor')}
              className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 dark:text-[#5b93ff] hover:underline"
            >
              View All <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {eventLog.slice(0, 4).map((evt) => {
              const dotClass = {
                SAFE: 'bg-emerald-400',
                INFO: 'bg-[#5b93ff]',
                WARN: 'bg-amber-400',
                ALERT: 'bg-rose-500',
              }[evt.level || 'INFO'];

              return (
                <div
                  key={evt.id}
                  className="flex items-start justify-between gap-3 py-1"
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <span
                      className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${dotClass}`}
                    />
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">
                        {evt.message}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400 truncate">
                        {evt.subtext || 'Client-side local execution'}
                      </div>
                    </div>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400 shrink-0 mt-0.5">
                    {evt.time}
                  </span>
                </div>
              );
            })}
          </div>
        </section>

        {/* Quick Tools 2x2 Grid */}
        <section className="xl:col-span-6 rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm">
          <div className="flex items-center gap-2.5 mb-4">
            <div className="w-7 h-7 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center">
              <Wrench className="w-4 h-4 text-slate-500 dark:text-slate-300" />
            </div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-white">
              Quick Tools
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <button
              type="button"
              onClick={() => onNavigate('scan')}
              className="group text-left p-4 rounded-xl border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#192338] hover:border-blue-500/40 hover:bg-slate-100 dark:hover:bg-[#1e2a42] transition-all flex items-center gap-3.5"
            >
              <div className="w-11 h-11 rounded-full bg-blue-500/15 border border-blue-500/25 flex items-center justify-center shrink-0">
                <Search className="w-5 h-5 text-blue-500 dark:text-[#5b93ff]" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-500 dark:group-hover:text-[#7aa7ff] transition-colors">
                  Full Scan
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Scan logs, text, or CSV
                </div>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('firewall')}
              className="group text-left p-4 rounded-xl border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#192338] hover:border-blue-500/40 hover:bg-slate-100 dark:hover:bg-[#1e2a42] transition-all flex items-center gap-3.5"
            >
              <div className="w-11 h-11 rounded-full bg-blue-500/15 border border-blue-500/25 flex items-center justify-center shrink-0">
                <Shield className="w-5 h-5 text-blue-500 dark:text-[#5b93ff]" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-500 dark:group-hover:text-[#7aa7ff] transition-colors">
                  Manage Firewall
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Verify zero network egress
                </div>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('privacy')}
              className="group text-left p-4 rounded-xl border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#192338] hover:border-blue-500/40 hover:bg-slate-100 dark:hover:bg-[#1e2a42] transition-all flex items-center gap-3.5"
            >
              <div className="w-11 h-11 rounded-full bg-blue-500/15 border border-blue-500/25 flex items-center justify-center shrink-0">
                <Lock className="w-5 h-5 text-blue-500 dark:text-[#5b93ff]" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-500 dark:group-hover:text-[#7aa7ff] transition-colors">
                  Privacy Check
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Inspect pseudonym vault
                </div>
              </div>
            </button>

            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="group text-left p-4 rounded-xl border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#192338] hover:border-blue-500/40 hover:bg-slate-100 dark:hover:bg-[#1e2a42] transition-all flex items-center gap-3.5"
            >
              <div className="w-11 h-11 rounded-full bg-blue-500/15 border border-blue-500/25 flex items-center justify-center shrink-0">
                <Settings className="w-5 h-5 text-blue-500 dark:text-[#5b93ff]" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-500 dark:group-hover:text-[#7aa7ff] transition-colors">
                  Security Settings
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Customize PII protection
                </div>
              </div>
            </button>
          </div>
        </section>
      </div>

      {/* Persisted Database Metrics & Recent Scan History */}
      {dashboardStats && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
          <section className="xl:col-span-5 rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">
              Database Telemetry (SQLite)
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#192338] border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Stored Scans</div>
                <div className="text-xl font-bold font-mono text-slate-900 dark:text-white mt-0.5">
                  {dashboardStats.total_scans}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#192338] border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Total PII Logged</div>
                <div className="text-xl font-bold font-mono text-[#5b93ff] mt-0.5">
                  {dashboardStats.total_pii_found}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#192338] border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Open Alerts</div>
                <div className="text-xl font-bold font-mono text-amber-500 mt-0.5">
                  {dashboardStats.unacknowledged_alerts}
                </div>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-[#192338] border border-slate-200 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Audit Events</div>
                <div className="text-xl font-bold font-mono text-emerald-500 mt-0.5">
                  {dashboardStats.total_activity_events}
                </div>
              </div>
            </div>
          </section>

          <section className="xl:col-span-7 rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Recent Scan History
              </h3>
              <button
                type="button"
                onClick={() => onNavigate('scan')}
                className="text-xs text-[#5b93ff] hover:underline"
              >
                New Scan →
              </button>
            </div>
            {dashboardStats.recent_scans?.length ? (
              <div className="space-y-2 max-h-40 overflow-auto custom-scrollbar">
                {dashboardStats.recent_scans.map((s) => (
                  <div
                    key={s.id}
                    className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl bg-slate-50 dark:bg-[#192338] border border-slate-200/80 dark:border-slate-800 text-xs"
                  >
                    <div className="min-w-0">
                      <div className="font-medium font-mono text-slate-900 dark:text-slate-100 truncate">
                        {s.filename || 'buffer_scan'}
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                        {s.scan_type} • {s.total_pii_found} PII • {s.luhn_rejected} Luhn rejected
                        {s.file_hash_sha256 ? ` • SHA-256: ${s.file_hash_sha256.slice(0, 12)}...` : ''}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-500 font-mono text-[10px] shrink-0">
                      {s.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No persisted scans yet. Click &ldquo;Run Quick Scan&rdquo; or upload a file to record scan history.
              </p>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
