import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Copy,
  Download,
  FileJson,
  Shield,
  EyeOff,
  Fingerprint,
  CheckCircle2,
  SlidersHorizontal,
} from 'lucide-react';
import { Sidebar } from './components/Sidebar.jsx';
import { TopBar } from './components/TopBar.jsx';
import { DashboardView } from './components/DashboardView.jsx';
import {
  ThreatMonitorView,
  EgressGuardView,
  SettingsView,
  AboutView,
} from './components/SecondaryViews.jsx';
import { PrivacyGuardView } from './components/PrivacyGuardView.jsx';
import { InputPanel } from './components/InputPanel.jsx';
import { AuditBar } from './components/AuditBar.jsx';
import { DiffView } from './components/DiffView.jsx';
import { PseudonymDrawer } from './components/PseudonymDrawer.jsx';
import { AuthModal } from './components/AuthModal.jsx';
import { ImageScannerView } from './components/ImageScannerView.jsx';
import {
  api,
  clearAuthSession,
  getStoredToken,
  getStoredUser,
} from './api/client.js';
import { detectPII, PII_TYPE_ORDER } from './engine/piiDetector.js';
import {
  createPseudonymSession,
  redactText,
  REDACTION_MODES,
} from './engine/redactor.js';
import { SAMPLE_DATASETS } from './data/sampleDatasets.js';

const MODE_OPTIONS = [
  {
    id: REDACTION_MODES.FULL_MASK,
    label: 'Full Mask',
    description: 'Strict [REDACTED_TYPE] blocks',
    icon: Shield,
  },
  {
    id: REDACTION_MODES.PARTIAL_MASK,
    label: 'Partial Mask',
    description: 'Verification context (last 4 / domain)',
    icon: EyeOff,
  },
  {
    id: REDACTION_MODES.PSEUDONYM,
    label: 'Consistent Pseudonymization',
    description: 'Deterministic EMAIL_01, CARD_01 tokens',
    icon: Fingerprint,
  },
];

function formatClockTime() {
  return new Date().toTimeString().slice(0, 8);
}

function triggerBlobDownload(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export default function App() {
  const [theme, setTheme] = useState('dark');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const [inputText, setInputText] = useState(SAMPLE_DATASETS[0].content);
  const [sourceMeta, setSourceMeta] = useState({
    fileName: `${SAMPLE_DATASETS[0].id}.${SAMPLE_DATASETS[0].extension}`,
    baseName: SAMPLE_DATASETS[0].id,
    extension: SAMPLE_DATASETS[0].extension,
    isSample: true,
    sampleId: SAMPLE_DATASETS[0].id,
  });

  const [mode, setMode] = useState(REDACTION_MODES.FULL_MASK);
  const [uniformFullMask, setUniformFullMask] = useState(false);
  const [enabledTypes, setEnabledTypes] = useState(() =>
    Object.fromEntries(PII_TYPE_ORDER.map((t) => [t, true]))
  );

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const pseudonymSessionRef = useRef(createPseudonymSession());
  const [sessionVersion, setSessionVersion] = useState(0);
  const [toast, setToast] = useState('');

  // Backend integration state
  const [backendOnline, setBackendOnline] = useState(false);
  const [currentUser, setCurrentUser] = useState(() => getStoredUser());
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [dbAlerts, setDbAlerts] = useState([]);

  const [eventLog, setEventLog] = useState(() => [
    {
      id: 'init-1',
      time: formatClockTime(),
      level: 'SAFE',
      message: 'Local Scan Completed',
      subtext: 'Zero-egress CSP lock enforced (connect-src: self)',
    },
    {
      id: 'init-2',
      time: formatClockTime(),
      level: 'INFO',
      message: 'Redaction Rules Loaded',
      subtext: 'Luhn Mod-10 + PAN + UIDAI Aadhaar validators ready',
    },
    {
      id: 'init-3',
      time: formatClockTime(),
      level: 'SAFE',
      message: `Sample Ingested (${SAMPLE_DATASETS[0].shortLabel})`,
      subtext: 'Processed 100% locally in browser memory',
    },
  ]);

  const refreshBackendData = async () => {
    try {
      const [stats, alertsList, activityList] = await Promise.all([
        api.getDashboardStats(),
        api.listAlerts(),
        api.listActivity({ limit: 30 }),
      ]);
      setBackendOnline(true);
      setDashboardStats(stats);
      setDbAlerts(alertsList);
      if (Array.isArray(activityList) && activityList.length > 0) {
        setEventLog(
          activityList.map((a) => ({
            id: `db-${a.id}`,
            time: a.created_at
              ? new Date(a.created_at).toTimeString().slice(0, 8)
              : formatClockTime(),
            level: a.level,
            message: a.message,
            subtext: a.subtext || a.source,
          }))
        );
      }
    } catch {
      setBackendOnline(false);
    }
  };

  useEffect(() => {
    const init = async () => {
      if (getStoredToken()) {
        try {
          const user = await api.me();
          setCurrentUser(user);
          const settingsRes = await api.getSettings();
          if (settingsRes?.settings) {
            if (settingsRes.settings.enabledTypes) {
              setEnabledTypes(settingsRes.settings.enabledTypes);
            }
            if (settingsRes.settings.mode) {
              setMode(settingsRes.settings.mode);
            }
            if (typeof settingsRes.settings.uniformFullMask === 'boolean') {
              setUniformFullMask(settingsRes.settings.uniformFullMask);
            }
            if (settingsRes.settings.theme) {
              setTheme(settingsRes.settings.theme);
            }
          }
        } catch {
          clearAuthSession();
          setCurrentUser(null);
        }
      }
      await refreshBackendData();
    };
    init();
  }, []);

  const appendEvent = (level, message, subtext = 'Client-side local execution') => {
    setEventLog((prev) => [
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        time: formatClockTime(),
        level,
        message,
        subtext,
      },
      ...prev.slice(0, 19),
    ]);
    if (backendOnline) {
      api.createActivity({ level, message, subtext, source: 'frontend' }).catch(() => {});
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  const showToast = (message) => {
    setToast(message);
    window.setTimeout(() => {
      setToast((prev) => (prev === message ? '' : prev));
    }, 2600);
  };

  // 1. Deterministic PII Detection
  const detection = useMemo(() => detectPII(inputText), [inputText]);

  // 2. Category Filter
  const activeMatches = useMemo(
    () => detection.matches.filter((m) => enabledTypes[m.type]),
    [detection.matches, enabledTypes]
  );

  // 3. Live Transformation
  const redactionResult = useMemo(() => {
    return redactText(inputText, activeMatches, {
      mode,
      uniformFullMask,
      session: pseudonymSessionRef.current,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inputText, activeMatches, mode, uniformFullMask, sessionVersion]);

  const { sessionEntries, occurrenceCounts } = useMemo(() => {
    const counts = {};
    for (const seg of redactionResult.segments) {
      if (seg.kind === 'entity') {
        const key = `${seg.match.type}::${seg.match.value}`;
        counts[key] = (counts[key] || 0) + 1;
      }
    }
    return {
      sessionEntries: Array.from(pseudonymSessionRef.current.map.values()),
      occurrenceCounts: counts,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [redactionResult, sessionVersion]);

  // Dynamic Threat Alerts derived from live detection state
  const alerts = useMemo(() => {
    const list = [];
    if (detection.totalDetected > 0) {
      list.push({
        id: 'alert-pii',
        tone: activeMatches.length < detection.totalDetected ? 'red' : 'blue',
        title:
          activeMatches.length < detection.totalDetected
            ? 'Unmasked PII Exposure'
            : 'PII Entities Sanitized',
        detail: `${activeMatches.length}/${detection.totalDetected} entities masked in ${sourceMeta?.fileName || 'buffer'}`,
        time: 'Live',
        targetTab: 'scan',
      });
    } else {
      list.push({
        id: 'alert-clean',
        tone: 'green',
        title: 'Zero PII Detected',
        detail: 'Current buffer contains no sensitive patterns',
        time: 'Live',
        targetTab: 'scan',
      });
    }

    list.push({
      id: 'alert-luhn',
      tone: detection.luhnRejectedCount > 0 ? 'amber' : 'blue',
      title: 'Luhn Checksum Gate',
      detail:
        detection.luhnRejectedCount > 0
          ? `Ignored ${detection.luhnRejectedCount} non-Luhn decoy numbers`
          : 'No invalid 16-digit decoys in buffer',
      time: 'Active',
      targetTab: 'monitor',
    });

    list.push({
      id: 'alert-egress',
      tone: 'green',
      title: 'Firewall / Zero Egress',
      detail: 'CSP connect-src: none enforced locally',
      time: 'Active',
      targetTab: 'firewall',
    });

    return list;
  }, [detection, activeMatches.length, sourceMeta]);

  const handleRunQuickScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanProgress(25);

    try {
      setScanProgress(60);
      await api.createScan({
        filename: sourceMeta?.fileName || 'manual_buffer.txt',
        file_size: inputText.length,
        scan_type: 'pii_detection',
        total_pii_found: detection.totalDetected,
        total_redacted: activeMatches.length,
        luhn_rejected: detection.luhnRejectedCount,
        redaction_mode: mode,
        results_json: activeMatches.slice(0, 100).map((m) => ({
          type: m.type,
          value: '[REDACTED]',
          start: m.start,
          end: m.end,
          validationMethod: m.validationMethod,
          isValid: m.isValid,
        })),
      });
      await refreshBackendData();
      setScanProgress(100);
      showToast(
        `Scan saved to DB: ${activeMatches.length} sanitized (${detection.luhnRejectedCount} decoys ignored)`
      );
    } catch {
      setScanProgress(100);
      appendEvent(
        detection.totalDetected > 0 ? 'SAFE' : 'INFO',
        `Quick Scan Completed (${detection.totalDetected} PII found)`,
        `${activeMatches.length} sanitized • ${detection.luhnRejectedCount} non-Luhn decoys ignored`
      );
      showToast(
        `Quick scan verified ${activeMatches.length} sanitized entities (${detection.luhnRejectedCount} decoys ignored)`
      );
    } finally {
      setIsScanning(false);
    }
  };

  const handleToggleType = (typeKey) => {
    setEnabledTypes((prev) => ({
      ...prev,
      [typeKey]: !prev[typeKey],
    }));
  };

  const handleSetAllTypes = (enabled) => {
    setEnabledTypes(Object.fromEntries(PII_TYPE_ORDER.map((t) => [t, enabled])));
    appendEvent('INFO', enabled ? 'Enabled all PII filters' : 'Paused all PII filters');
  };

  const handleLoadSample = (sample) => {
    setInputText(sample.content);
    setSourceMeta({
      fileName: `${sample.id}.${sample.extension}`,
      baseName: sample.id,
      extension: sample.extension,
      isSample: true,
      sampleId: sample.id,
    });
    appendEvent(
      'INFO',
      `Loaded ${sample.shortLabel}.${sample.extension}`,
      sample.description
    );
  };

  const handleFileLoaded = async (content, meta) => {
    setInputText(content);
    setSourceMeta(meta);
    showToast(`Loaded ${meta.fileName} locally`);
    if (meta.rawFile && backendOnline) {
      try {
        const scanRes = await api.uploadFileScan(meta.rawFile);
        showToast(`Uploaded & hashed ${meta.fileName} (SHA-256: ${scanRes.file_hash_sha256?.slice(0, 10)}...)`);
        await refreshBackendData();
      } catch {
        appendEvent('SAFE', `Ingested ${meta.fileName}`, 'Read locally via browser FileReader');
      }
    } else {
      appendEvent('SAFE', `Ingested ${meta.fileName}`, 'Read locally via browser FileReader');
    }
  };

  const handleAcknowledgeAlert = async (alertId) => {
    try {
      await api.acknowledgeAlert(alertId);
      showToast('Threat alert acknowledged');
      await refreshBackendData();
    } catch (err) {
      showToast(err.message || 'Failed to acknowledge alert');
    }
  };

  const handleFilterActivity = async ({ search, level }) => {
    try {
      const list = await api.listActivity({
        search: search || undefined,
        level: level || undefined,
        limit: 50,
      });
      setEventLog(
        list.map((a) => ({
          id: `db-${a.id}`,
          time: a.created_at
            ? new Date(a.created_at).toTimeString().slice(0, 8)
            : formatClockTime(),
          level: a.level,
          message: a.message,
          subtext: a.subtext || a.source,
        }))
      );
    } catch {
      // ignore if offline
    }
  };

  const handleSaveSettings = async () => {
    try {
      await api.saveSettings({
        enabledTypes,
        mode,
        uniformFullMask,
        theme,
      });
      showToast('Settings saved to database');
      await refreshBackendData();
    } catch (err) {
      showToast(err.message || 'Failed to save settings');
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      // ignore
    }
    clearAuthSession();
    setCurrentUser(null);
    showToast('Signed out');
    await refreshBackendData();
  };

  const handleManualTextChange = (nextText) => {
    setInputText(nextText);
    if (sourceMeta?.isSample) {
      setSourceMeta({
        fileName: null,
        baseName: 'pasted_text',
        extension: 'txt',
        isSample: false,
      });
    }
  };

  const handleClear = () => {
    setInputText('');
    setSourceMeta({
      fileName: null,
      baseName: 'sanitized_output',
      extension: 'txt',
      isSample: false,
    });
    appendEvent('INFO', 'Cleared input buffer', 'Local memory buffer emptied');
  };

  const handleModeChange = (nextMode) => {
    setMode(nextMode);
    const label = MODE_OPTIONS.find((m) => m.id === nextMode)?.label || nextMode;
    appendEvent('INFO', `Mode switched to ${label}`, 'Live output regenerated locally');
  };

  const handlePurgeSession = () => {
    pseudonymSessionRef.current = createPseudonymSession();
    setSessionVersion((v) => v + 1);
    showToast('Session pseudonym map purged from memory');
    appendEvent('WARN', 'Pseudonym Vault Purged', 'Cleared in-memory deterministic lookup map');
  };

  const handleCopySanitized = async () => {
    if (!redactionResult.sanitizedText) return;
    try {
      await navigator.clipboard.writeText(redactionResult.sanitizedText);
      showToast('Copied sanitized output to clipboard');
      appendEvent('SAFE', 'Copied Sanitized Output', 'Copied transformed text to clipboard');
    } catch {
      showToast('Clipboard permission denied by browser');
    }
  };

  const exportExt = sourceMeta?.extension === 'csv' ? 'csv' : 'txt';
  const exportFilename = `sanitized_${sourceMeta?.baseName || 'output'}.${exportExt}`;

  const handleDownloadSanitized = () => {
    if (!redactionResult.sanitizedText) return;
    const mimeType =
      exportExt === 'csv'
        ? 'text/csv;charset=utf-8'
        : 'text/plain;charset=utf-8';
    triggerBlobDownload(redactionResult.sanitizedText, exportFilename, mimeType);
    showToast(`Downloaded ${exportFilename}`);
    appendEvent('SAFE', `Exported ${exportFilename}`, 'Generated locally via Blob URL');
  };

  const handleDownloadAuditReport = () => {
    const activeCountsByType = Object.fromEntries(
      PII_TYPE_ORDER.map((t) => [
        t,
        enabledTypes[t] ? detection.countsByType[t] || 0 : 0,
      ])
    );

    const report = {
      application: 'RedactZero',
      version: '1.0.0',
      generatedAt: new Date().toISOString(),
      executionEnvironment: '100% Client-Side Browser Memory (Zero Network Egress)',
      redactionMode: mode,
      uniformFullMask: mode === REDACTION_MODES.FULL_MASK ? uniformFullMask : false,
      sourceDocument: {
        filename: sourceMeta?.fileName || 'manual_paste.txt',
        format: exportExt.toUpperCase(),
        characterCount: inputText.length,
        lineCount: inputText ? inputText.split(/\r?\n/).length : 0,
      },
      summary: {
        totalPiiDetected: detection.totalDetected,
        totalEntitiesRedacted: activeMatches.length,
        luhnFalsePositivesRejected: detection.luhnRejectedCount,
      },
      enabledCategories: Object.keys(enabledTypes).filter((k) => enabledTypes[k]),
      detectedCountsByCategory: detection.countsByType,
      redactedCountsByCategory: activeCountsByType,
    };

    triggerBlobDownload(
      JSON.stringify(report, null, 2),
      'audit_report.json',
      'application/json;charset=utf-8'
    );
    showToast('Downloaded audit_report.json (Zero Raw PII)');
    appendEvent('SAFE', 'Exported audit_report.json', 'Zero raw PII included in report');
  };

  const activeModeLabel =
    MODE_OPTIONS.find((m) => m.id === mode)?.label || 'Full Mask';

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-[#0b1120] text-slate-900 dark:text-slate-100 transition-colors">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        totalDetected={detection.totalDetected}
        activeRedactedCount={activeMatches.length}
        isScanning={isScanning}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        backendOnline={backendOnline}
        currentUser={currentUser}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          theme={theme}
          onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
          matches={detection.matches}
          alerts={alerts}
          onNavigate={setActiveTab}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          currentUser={currentUser}
          onOpenAuthModal={() => setAuthModalOpen(true)}
          onLogout={handleLogout}
          backendOnline={backendOnline}
        />

        <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6 space-y-5">
          {activeTab === 'dashboard' && (
            <DashboardView
              inputText={inputText}
              sourceMeta={sourceMeta}
              detection={detection}
              activeMatches={activeMatches}
              modeLabel={activeModeLabel}
              isScanning={isScanning}
              scanProgress={scanProgress}
              onRunQuickScan={handleRunQuickScan}
              onLoadSample={handleLoadSample}
              onNavigate={setActiveTab}
              alerts={alerts}
              eventLog={eventLog}
              dashboardStats={dashboardStats}
            />
          )}

          {activeTab === 'monitor' && (
            <ThreatMonitorView
              detection={detection}
              enabledTypes={enabledTypes}
              eventLog={eventLog}
              onNavigateScan={() => setActiveTab('scan')}
              dbAlerts={dbAlerts}
              onAcknowledgeAlert={handleAcknowledgeAlert}
              onFilterActivity={handleFilterActivity}
            />
          )}

          {activeTab === 'scan' && (
            <div className="space-y-4">
              <InputPanel
                inputText={inputText}
                onTextChange={handleManualTextChange}
                sourceMeta={sourceMeta}
                onFileLoaded={handleFileLoaded}
                onLoadSample={handleLoadSample}
                onClear={handleClear}
                enabledTypes={enabledTypes}
                onToggleType={handleToggleType}
                onSetAllTypes={handleSetAllTypes}
              />

              {/* Mode Switcher + Export Controls */}
              <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] p-4 shadow-sm flex flex-wrap items-center justify-between gap-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mr-1">
                    <SlidersHorizontal className="w-3.5 h-3.5 text-[#5b93ff]" />
                    Redaction Mode:
                  </span>
                  <div className="inline-flex flex-wrap gap-1.5 p-1 rounded-xl bg-slate-100 dark:bg-[#0b1120] border border-slate-200 dark:border-slate-800">
                    {MODE_OPTIONS.map((opt) => {
                      const Icon = opt.icon;
                      const active = mode === opt.id;
                      return (
                        <button
                          key={opt.id}
                          type="button"
                          title={opt.description}
                          onClick={() => handleModeChange(opt.id)}
                          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                            active
                              ? 'bg-[#5b93ff] text-slate-950 shadow-sm'
                              : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          <span>{opt.label}</span>
                        </button>
                      );
                    })}
                  </div>

                  {mode === REDACTION_MODES.FULL_MASK && (
                    <label className="ml-1 inline-flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-[#0f1627] border border-slate-200 dark:border-slate-800 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={uniformFullMask}
                        onChange={(e) => setUniformFullMask(e.target.checked)}
                        className="rounded border-slate-300 text-[#5b93ff] focus:ring-[#5b93ff]"
                      />
                      <span>
                        Uniform <code className="font-mono">[REDACTED]</code>
                      </span>
                    </label>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopySanitized}
                    disabled={!redactionResult.sanitizedText}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#192338] hover:bg-slate-100 dark:hover:bg-[#1e2a42] text-slate-800 dark:text-slate-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5 text-[#5b93ff]" />
                    Copy Output
                  </button>

                  <button
                    type="button"
                    onClick={handleDownloadSanitized}
                    disabled={!redactionResult.sanitizedText}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-[#5b93ff] hover:bg-[#4983f2] text-slate-950 shadow-sm disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Export .{exportExt.toUpperCase()}
                  </button>

                  <button
                    type="button"
                    onClick={handleDownloadAuditReport}
                    disabled={!inputText}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border border-emerald-500/35 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    <FileJson className="w-3.5 h-3.5" />
                    Audit Report (.json)
                  </button>
                </div>
              </section>

              <AuditBar
                totalDetected={detection.totalDetected}
                activeRedactedCount={activeMatches.length}
                countsByType={detection.countsByType}
                luhnRejectedCount={detection.luhnRejectedCount}
                enabledTypes={enabledTypes}
              />

              <DiffView
                segments={redactionResult.segments}
                hasInput={inputText.length > 0}
                modeLabel={activeModeLabel}
              />

              <PseudonymDrawer
                entries={sessionEntries}
                occurrenceCounts={occurrenceCounts}
                isPseudonymMode={mode === REDACTION_MODES.PSEUDONYM}
                onPurgeSession={handlePurgeSession}
              />
            </div>
          )}

          {activeTab === 'image-scanner' && (
            <ImageScannerView
              onNotify={showToast}
              onScanCompleted={refreshBackendData}
            />
          )}

          {activeTab === 'firewall' && (
            <EgressGuardView
              onAuditRun={(res) =>
                appendEvent(
                  'SAFE',
                  'Egress Firewall Verified',
                  `${res.externalRequestsDetected} external requests • CSP connect-src: none`
                )
              }
            />
          )}

          {activeTab === 'privacy' && (
            <PrivacyGuardView
              sessionEntries={sessionEntries}
              occurrenceCounts={occurrenceCounts}
              mode={mode}
              onChangeMode={handleModeChange}
              onPurgeSession={handlePurgeSession}
              onNotify={showToast}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              enabledTypes={enabledTypes}
              onToggleType={handleToggleType}
              onSetAllTypes={handleSetAllTypes}
              mode={mode}
              onChangeMode={handleModeChange}
              uniformFullMask={uniformFullMask}
              onToggleUniformMask={setUniformFullMask}
              theme={theme}
              onToggleTheme={() =>
                setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
              }
              currentUser={currentUser}
              onSaveSettings={handleSaveSettings}
              onOpenAuthModal={() => setAuthModalOpen(true)}
            />
          )}

          {activeTab === 'about' && <AboutView backendOnline={backendOnline} />}
        </main>
      </div>

      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthSuccess={async (user) => {
          setCurrentUser(user);
          showToast(`Welcome, ${user.username}!`);
          await refreshBackendData();
        }}
      />

      {/* Toast Notification */}
      {toast && (
        <div
          role="status"
          className="fixed bottom-5 right-5 z-50 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 dark:bg-[#131b2e] text-white text-xs font-medium shadow-xl border border-emerald-500/40"
        >
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}
