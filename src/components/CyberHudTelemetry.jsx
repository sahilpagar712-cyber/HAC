import React, { useMemo, useState } from 'react';
import {
  Lock,
  AlertTriangle,
  ShieldCheck,
  Cpu,
  WifiOff,
  KeyRound,
  ChevronDown,
  ChevronUp,
  Activity,
} from 'lucide-react';

function HudDotMatrix({ className = 'text-cyan-400/50' }) {
  return (
    <div className={`hud-dot-matrix ${className}`} aria-hidden="true">
      {Array.from({ length: 8 }).map((_, idx) => (
        <span key={idx} />
      ))}
    </div>
  );
}

function HudCornerBrackets({ colorClass = 'border-cyan-400/70' }) {
  return (
    <>
      <span className={`pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 ${colorClass}`} />
      <span className={`pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 ${colorClass}`} />
      <span className={`pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 ${colorClass}`} />
      <span className={`pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 ${colorClass}`} />
    </>
  );
}

function CircularHudGauge({ valuePct, label, sublabel, color = 'cyan' }) {
  const radius = 32;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, valuePct));
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  const strokeMap = {
    cyan: 'stroke-cyan-400',
    emerald: 'stroke-emerald-400',
    amber: 'stroke-amber-400',
    rose: 'stroke-rose-400',
  };

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative w-20 h-20 flex items-center justify-center">
        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
          <circle
            cx="40"
            cy="40"
            r={radius}
            fill="none"
            strokeWidth="5"
            className="stroke-slate-200 dark:stroke-slate-800"
          />
          <circle
            cx="40"
            cy="40"
            r={radius}
            fill="none"
            strokeWidth="5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={`${strokeMap[color] || strokeMap.cyan} transition-all duration-500`}
          />
        </svg>
        <span className="absolute text-sm font-mono font-bold text-slate-900 dark:text-white">
          {clamped}%
        </span>
      </div>
      <span className="text-[10px] font-bold tracking-[0.16em] uppercase text-slate-600 dark:text-cyan-300">
        {label}
      </span>
      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-400">
        {sublabel}
      </span>
    </div>
  );
}

function MiniBarMeter({ bars, activeCount, accent = 'bg-cyan-400' }) {
  return (
    <div className="flex items-end gap-[3px] h-7" aria-hidden="true">
      {bars.map((height, idx) => {
        const isLit = idx < activeCount;
        return (
          <span
            key={idx}
            style={{ height: `${height}%` }}
            className={`w-1 rounded-t-sm transition-all duration-300 ${
              isLit ? accent : 'bg-slate-200 dark:bg-slate-800'
            }`}
          />
        );
      })}
    </div>
  );
}

export function CyberHudTelemetry({
  inputText,
  detection,
  activeMatches,
  luhnRejectedCount,
  sessionSize,
  eventLog,
  modeLabel,
}) {
  const [collapsed, setCollapsed] = useState(false);

  const totalDetected = detection.totalDetected;
  const activeCount = activeMatches.length;
  const coveragePct =
    totalDetected === 0 ? 100 : Math.round((activeCount / totalDetected) * 100);

  const counts = detection.countsByType;
  const contactTotal = (counts.EMAIL || 0) + (counts.PHONE || 0);
  const idInfraTotal =
    (counts.IP_ADDRESS || 0) + (counts.PAN || 0) + (counts.AADHAAR || 0);
  const cardTotal = counts.CREDIT_CARD || 0;

  const pctOfTotal = (part) =>
    totalDetected === 0 ? 0 : Math.round((part / totalDetected) * 100);

  // Compute live PII hit density across 16 buckets of the current document
  const sparklinePoints = useMemo(() => {
    const bucketCount = 16;
    const buckets = new Array(bucketCount).fill(0);
    const len = Math.max(1, inputText.length);
    for (const m of detection.matches) {
      const idx = Math.min(
        bucketCount - 1,
        Math.floor((m.start / len) * bucketCount)
      );
      buckets[idx] += 1;
    }
    const maxVal = Math.max(1, ...buckets);
    const width = 300;
    const height = 76;
    const coords = buckets.map((val, i) => {
      const x = (i / (bucketCount - 1)) * width;
      const y = height - 8 - (val / maxVal) * (height - 18);
      return [x, y];
    });
    const linePath = coords
      .map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`)
      .join(' ');
    const areaPath = `${linePath} L${width},${height} L0,${height} Z`;
    return { linePath, areaPath, peak: Math.max(...buckets) };
  }, [inputText, detection.matches]);

  const luhnBars = [35, 55, 70, 45, 85, 65, 90, 50, 75, 95, 60, 80];
  const cspBars = [60, 80, 95, 70, 90, 85, 100, 75, 90, 80, 95, 85];
  const vaultBars = [30, 50, 40, 75, 60, 85, 45, 70, 55, 80, 65, 90];

  return (
    <section className="space-y-3">
      {/* Compact HUD Control Bar */}
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2 text-[11px] font-bold tracking-[0.18em] uppercase text-cyan-700 dark:text-cyan-300">
          <Activity className="w-3.5 h-3.5 text-cyan-500" />
          <span>SOC Privacy Telemetry &amp; Detection Matrix</span>
        </div>
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          className="inline-flex items-center gap-1 text-[11px] font-mono uppercase tracking-wider text-slate-500 dark:text-cyan-400/80 hover:text-cyan-500 transition-colors"
        >
          {collapsed ? (
            <>
              Expand HUD <ChevronDown className="w-3.5 h-3.5" />
            </>
          ) : (
            <>
              Minimize HUD <ChevronUp className="w-3.5 h-3.5" />
            </>
          )}
        </button>
      </div>

      {!collapsed && (
        <div className="space-y-3">
          {/* Top Telemetry Row: 3 Circular HUD Rings + 3 Stacked Engine Status Panels */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-12 gap-3">
            {/* Ring 1: System Secure / Zero Egress */}
            <div className="xl:col-span-3 hud-panel rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 p-4 flex items-center justify-center">
              <HudCornerBrackets colorClass="border-cyan-400/70" />
              <div className="flex flex-col items-center text-center">
                <div className="relative w-28 h-28 flex items-center justify-center">
                  <svg className="w-28 h-28 animate-spin-slow" viewBox="0 0 120 120">
                    <circle
                      cx="60"
                      cy="60"
                      r="54"
                      fill="none"
                      strokeWidth="2"
                      strokeDasharray="34 14 18 10"
                      className="stroke-cyan-500/60"
                    />
                    <circle
                      cx="60"
                      cy="60"
                      r="46"
                      fill="none"
                      strokeWidth="4"
                      strokeDasharray="70 22 40 16"
                      className="stroke-cyan-400"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <Lock className="w-6 h-6 text-cyan-500 dark:text-cyan-300 mb-1" />
                    <span className="text-[10px] font-bold tracking-[0.14em] uppercase text-cyan-700 dark:text-cyan-300">
                      Zero Egress
                    </span>
                    <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400">
                      All shields active
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Ring 2: PII Threat / Exposure Detected */}
            <div className="xl:col-span-3 hud-panel rounded-xl border border-slate-200 dark:border-rose-500/30 bg-white dark:bg-slate-950/80 p-4 flex items-center justify-center">
              <HudCornerBrackets
                colorClass={
                  totalDetected > 0 ? 'border-rose-500/80' : 'border-emerald-400/80'
                }
              />
              <div className="flex flex-col items-center text-center">
                <div className="relative w-28 h-28 flex items-center justify-center">
                  <svg
                    className="w-28 h-28 animate-spin-reverse-slow"
                    viewBox="0 0 120 120"
                  >
                    <circle
                      cx="60"
                      cy="60"
                      r="54"
                      fill="none"
                      strokeWidth="2"
                      strokeDasharray="28 12 20 14"
                      className={
                        totalDetected > 0
                          ? 'stroke-rose-500/60'
                          : 'stroke-emerald-500/60'
                      }
                    />
                    <circle
                      cx="60"
                      cy="60"
                      r="46"
                      fill="none"
                      strokeWidth="4"
                      strokeDasharray="55 20 35 18"
                      className={
                        totalDetected > 0 ? 'stroke-rose-500' : 'stroke-emerald-400'
                      }
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <AlertTriangle
                      className={`w-6 h-6 mb-1 ${
                        totalDetected > 0
                          ? 'text-rose-500'
                          : 'text-emerald-400'
                      }`}
                    />
                    <span
                      className={`text-[10px] font-bold tracking-[0.14em] uppercase ${
                        totalDetected > 0
                          ? 'text-rose-600 dark:text-rose-400'
                          : 'text-emerald-600 dark:text-emerald-300'
                      }`}
                    >
                      {totalDetected > 0 ? 'PII Detected' : 'Clean Buffer'}
                    </span>
                    <span className="text-[11px] font-mono font-bold text-slate-800 dark:text-slate-200">
                      {totalDetected} {totalDetected === 1 ? 'entity' : 'entities'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Ring 3: Sanitization Coverage % */}
            <div className="xl:col-span-3 hud-panel rounded-xl border border-slate-200 dark:border-emerald-500/30 bg-white dark:bg-slate-950/80 p-4 flex flex-col items-center justify-center gap-2">
              <HudCornerBrackets colorClass="border-emerald-400/75" />
              <div className="relative w-24 h-24 flex items-center justify-center">
                <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    fill="none"
                    strokeWidth="6"
                    className="stroke-slate-200 dark:stroke-slate-800"
                  />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    fill="none"
                    strokeWidth="6"
                    strokeLinecap="round"
                    strokeDasharray={2 * Math.PI * 40}
                    strokeDashoffset={
                      2 * Math.PI * 40 * (1 - coveragePct / 100)
                    }
                    className="stroke-emerald-400 transition-all duration-500"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 mb-0.5" />
                  <span className="text-[9px] font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-300">
                    Sanitized
                  </span>
                  <span className="text-sm font-mono font-bold text-slate-900 dark:text-white">
                    {coveragePct}%
                  </span>
                </div>
              </div>
              <div className="w-full max-w-[170px] h-1.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all duration-500"
                  style={{ width: `${coveragePct}%` }}
                />
              </div>
            </div>

            {/* Right Stack: 3 Engine Status Modules */}
            <div className="xl:col-span-3 flex flex-col gap-2">
              <div className="hud-panel flex-1 rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 px-3.5 py-2.5 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-[10px] font-bold tracking-[0.14em] uppercase text-slate-800 dark:text-slate-100 truncate">
                      Luhn Mod-10 Gate
                    </div>
                    <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      ACTIVE &bull; {luhnRejectedCount} IGNORED
                    </div>
                  </div>
                </div>
                <MiniBarMeter
                  bars={luhnBars}
                  activeCount={luhnRejectedCount > 0 ? 11 : 7}
                  accent="bg-cyan-400"
                />
              </div>

              <div className="hud-panel flex-1 rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 px-3.5 py-2.5 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
                    <WifiOff className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-[10px] font-bold tracking-[0.14em] uppercase text-slate-800 dark:text-slate-100 truncate">
                      CSP Network Lock
                    </div>
                    <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      CONNECT-SRC: NONE
                    </div>
                  </div>
                </div>
                <MiniBarMeter
                  bars={cspBars}
                  activeCount={12}
                  accent="bg-emerald-400"
                />
              </div>

              <div className="hud-panel flex-1 rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 px-3.5 py-2.5 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center shrink-0">
                    <KeyRound className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-[10px] font-bold tracking-[0.14em] uppercase text-slate-800 dark:text-slate-100 truncate">
                      Mode: {modeLabel}
                    </div>
                    <div className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                      VAULT: {sessionSize} KEYS
                    </div>
                  </div>
                </div>
                <MiniBarMeter
                  bars={vaultBars}
                  activeCount={Math.min(12, Math.max(4, sessionSize + 4))}
                  accent="bg-cyan-400"
                />
              </div>
            </div>
          </div>

          {/* Second Telemetry Row: Density Sparkline, Category Donut Rings, Live Security Event Log */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
            {/* Document PII Density Analytics */}
            <div className="lg:col-span-4 hud-panel rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 p-4 flex flex-col justify-between">
              <HudCornerBrackets colorClass="border-cyan-400/60" />
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="text-[11px] font-bold tracking-[0.16em] uppercase text-slate-800 dark:text-cyan-300">
                    PII Density Analytics
                  </h3>
                  <p className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                    Spatial distribution across buffer ({sparklinePoints.peak} peak/seg)
                  </p>
                </div>
                <HudDotMatrix />
              </div>

              <div className="relative mt-1">
                <svg
                  viewBox="0 0 300 76"
                  className="w-full h-20 overflow-visible"
                  preserveAspectRatio="none"
                >
                  <defs>
                    <linearGradient id="piiAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                      <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.02" />
                    </linearGradient>
                  </defs>
                  <line
                    x1="0"
                    y1="74"
                    x2="300"
                    y2="74"
                    className="stroke-slate-200 dark:stroke-slate-800"
                    strokeWidth="1"
                  />
                  <path d={sparklinePoints.areaPath} fill="url(#piiAreaGrad)" />
                  <path
                    d={sparklinePoints.linePath}
                    fill="none"
                    stroke="#22d3ee"
                    strokeWidth="2"
                  />
                </svg>
                <div className="flex justify-between text-[9px] font-mono text-slate-400 mt-1">
                  <span>OFFSET 0%</span>
                  <span>25%</span>
                  <span>50%</span>
                  <span>75%</span>
                  <span>100%</span>
                </div>
              </div>
            </div>

            {/* Category Breakdown Rings */}
            <div className="lg:col-span-4 hud-panel rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 p-4 flex flex-col justify-between">
              <HudCornerBrackets colorClass="border-cyan-400/60" />
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-[11px] font-bold tracking-[0.16em] uppercase text-slate-800 dark:text-cyan-300">
                  Category Telemetry Share
                </h3>
                <HudDotMatrix />
              </div>

              <div className="grid grid-cols-3 gap-2 items-center">
                <CircularHudGauge
                  valuePct={pctOfTotal(contactTotal)}
                  label="Contacts"
                  sublabel={`${contactTotal} Email/Tel`}
                  color="cyan"
                />
                <CircularHudGauge
                  valuePct={pctOfTotal(idInfraTotal)}
                  label="ID & Net"
                  sublabel={`${idInfraTotal} IP/PAN/UID`}
                  color="emerald"
                />
                <CircularHudGauge
                  valuePct={pctOfTotal(cardTotal)}
                  label="Cards"
                  sublabel={`${cardTotal} Luhn OK`}
                  color="amber"
                />
              </div>
            </div>

            {/* Security Event Log */}
            <div className="lg:col-span-4 hud-panel rounded-xl border border-slate-200 dark:border-cyan-500/30 bg-white dark:bg-slate-950/80 p-4 flex flex-col">
              <HudCornerBrackets colorClass="border-cyan-400/60" />
              <div className="flex items-center justify-between mb-2.5">
                <h3 className="text-[11px] font-bold tracking-[0.16em] uppercase text-slate-800 dark:text-cyan-300">
                  Security Event Log
                </h3>
                <HudDotMatrix />
              </div>

              <div className="space-y-1.5 max-h-[112px] overflow-auto custom-scrollbar pr-1 font-mono text-[11px]">
                {eventLog.map((evt) => {
                  const badgeColors = {
                    INFO: 'text-cyan-600 dark:text-cyan-400',
                    SAFE: 'text-emerald-600 dark:text-emerald-400',
                    WARN: 'text-amber-600 dark:text-amber-400',
                    ALERT: 'text-rose-600 dark:text-rose-400',
                  };
                  const dotColors = {
                    INFO: 'bg-cyan-400',
                    SAFE: 'bg-emerald-400',
                    WARN: 'bg-amber-400',
                    ALERT: 'bg-rose-400',
                  };
                  return (
                    <div
                      key={evt.id}
                      className="flex items-center justify-between gap-2 py-0.5 border-b border-slate-100 dark:border-slate-800/70 last:border-b-0"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                            dotColors[evt.level] || dotColors.INFO
                          }`}
                        />
                        <span className="text-slate-400 shrink-0">{evt.time}</span>
                        <span className="text-slate-700 dark:text-slate-200 truncate">
                          {evt.message}
                        </span>
                      </div>
                      <span
                        className={`font-bold text-[10px] shrink-0 ${
                          badgeColors[evt.level] || badgeColors.INFO
                        }`}
                      >
                        {evt.level}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
