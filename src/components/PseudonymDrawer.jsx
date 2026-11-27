import React, { useState } from 'react';
import {
  KeyRound,
  ChevronDown,
  ChevronUp,
  Trash2,
  Eye,
  EyeOff,
} from 'lucide-react';
import { PII_TYPES } from '../engine/piiDetector.js';

export function PseudonymDrawer({
  entries,
  occurrenceCounts,
  isPseudonymMode,
  onPurgeSession,
}) {
  const [isOpen, setIsOpen] = useState(true);
  const [revealRaw, setRevealRaw] = useState(true);

  if (!isPseudonymMode && entries.length === 0) {
    return null;
  }

  return (
    <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] shadow-sm overflow-hidden">
      <div className="px-4 sm:px-5 py-3 bg-slate-50/80 dark:bg-[#0f1627] flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={() => setIsOpen((o) => !o)}
          className="flex items-center gap-2.5 text-left"
        >
          <KeyRound className="w-4 h-4 text-[#5b93ff]" />
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Session Pseudonymization Lookup Map
          </span>
          <span className="px-2 py-0.5 rounded-full text-xs font-mono font-semibold bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
            {entries.length} {entries.length === 1 ? 'mapping' : 'mappings'}
          </span>
          {isOpen ? (
            <ChevronUp className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </button>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setRevealRaw((r) => !r)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
          >
            {revealRaw ? (
              <>
                <EyeOff className="w-3.5 h-3.5" />
                Hide Raw Values
              </>
            ) : (
              <>
                <Eye className="w-3.5 h-3.5" />
                Show Raw Values
              </>
            )}
          </button>

          <button
            type="button"
            onClick={onPurgeSession}
            disabled={entries.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Purge Session Map
          </button>
        </div>
      </div>

      {isOpen && (
        <div className="border-t border-slate-200 dark:border-slate-800">
          {entries.length === 0 ? (
            <div className="px-5 py-6 text-xs text-slate-500 dark:text-slate-400 text-center">
              No pseudonym mappings recorded yet in this session. Detected entities in Consistent Pseudonymization mode will populate deterministically here.
            </div>
          ) : (
            <div className="max-h-64 overflow-auto custom-scrollbar">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 uppercase tracking-wider text-[11px]">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold">Pseudonym Token</th>
                    <th className="px-4 py-2.5 font-semibold">Category</th>
                    <th className="px-4 py-2.5 font-semibold">Original Value (Local Memory Only)</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Doc Hits</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/80 dark:divide-slate-800/80 font-mono">
                  {entries.map((entry) => {
                    const meta = PII_TYPES[entry.type];
                    const hits = occurrenceCounts[entry.key] || 0;
                    return (
                      <tr
                        key={entry.key}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      >
                        <td className="px-4 py-2">
                          <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 font-semibold">
                            {entry.placeholder}
                          </span>
                        </td>
                        <td className="px-4 py-2 font-sans">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-medium border ${
                              meta?.badgeClass || ''
                            }`}
                          >
                            {meta?.shortLabel || entry.type}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-slate-700 dark:text-slate-300 break-all">
                          {revealRaw ? entry.rawValue : '••••••••••••••••'}
                        </td>
                        <td className="px-4 py-2 text-right text-slate-500 dark:text-slate-400">
                          {hits}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
