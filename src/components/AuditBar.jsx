import React from 'react';
import { ShieldAlert, ScanSearch, CheckCircle2 } from 'lucide-react';
import { PII_TYPES, PII_TYPE_ORDER } from '../engine/piiDetector.js';

export function AuditBar({
  totalDetected,
  activeRedactedCount,
  countsByType,
  luhnRejectedCount,
  enabledTypes,
}) {
  return (
    <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] px-4 sm:px-5 py-3.5 shadow-sm flex flex-wrap items-center justify-between gap-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <div className="flex items-center gap-2 pr-3 border-r border-slate-200 dark:border-slate-800">
          <ScanSearch className="w-4 h-4 text-emerald-500" />
          <div className="text-xs">
            <span className="text-slate-500 dark:text-slate-400">Detected: </span>
            <span className="font-bold font-mono text-slate-900 dark:text-white text-sm">
              {totalDetected}
            </span>
            {activeRedactedCount !== totalDetected && (
              <span className="ml-1.5 text-[11px] text-slate-400">
                ({activeRedactedCount} active)
              </span>
            )}
          </div>
        </div>

        {PII_TYPE_ORDER.map((typeKey) => {
          const meta = PII_TYPES[typeKey];
          const count = countsByType[typeKey] || 0;
          const isEnabled = enabledTypes[typeKey];

          return (
            <div
              key={typeKey}
              title={`${meta.label}: ${count} detected (${meta.validationMethod})`}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-opacity ${
                isEnabled
                  ? meta.badgeClass
                  : 'bg-slate-100 dark:bg-slate-800/40 text-slate-400 border-slate-200 dark:border-slate-800 opacity-50 line-through'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${meta.dotClass}`} />
              <span className="font-medium">{meta.shortLabel}</span>
              <span className="font-mono font-bold">{count}</span>
            </div>
          );
        })}
      </div>

      {/* Luhn False-Positive Rejection Indicator */}
      <div
        title="13–19 digit sequences that matched card formatting but failed the Luhn Mod-10 checksum (e.g., order IDs, tracking numbers) and were safely ignored."
        className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium border ${
          luhnRejectedCount > 0
            ? 'bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-300'
            : 'bg-slate-100 dark:bg-slate-800/70 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300'
        }`}
      >
        {luhnRejectedCount > 0 ? (
          <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0" />
        ) : (
          <CheckCircle2 className="w-4 h-4 text-slate-400 shrink-0" />
        )}
        <span>Non-Luhn False Positives Ignored:</span>
        <span className="font-mono font-bold text-sm">{luhnRejectedCount}</span>
      </div>
    </section>
  );
}
