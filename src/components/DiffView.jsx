import React, { useRef, useState } from 'react';
import { Eye, Shield, WrapText } from 'lucide-react';
import { PII_TYPES } from '../engine/piiDetector.js';

export function DiffView({ segments, hasInput, modeLabel }) {
  const leftPaneRef = useRef(null);
  const rightPaneRef = useRef(null);
  const syncingRef = useRef(null);
  const [wrapLines, setWrapLines] = useState(true);

  const handleScroll = (source) => {
    if (syncingRef.current && syncingRef.current !== source) {
      return;
    }
    const fromEl = source === 'left' ? leftPaneRef.current : rightPaneRef.current;
    const toEl = source === 'left' ? rightPaneRef.current : leftPaneRef.current;
    if (!fromEl || !toEl) return;

    syncingRef.current = source;
    toEl.scrollTop = fromEl.scrollTop;
    toEl.scrollLeft = fromEl.scrollLeft;

    requestAnimationFrame(() => {
      syncingRef.current = null;
    });
  };

  const preClass = `p-4 text-xs sm:text-[13px] leading-6 font-mono min-h-[280px] max-h-[460px] overflow-auto custom-scrollbar ${
    wrapLines ? 'whitespace-pre-wrap break-words' : 'whitespace-pre'
  }`;

  return (
    <section className="rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#131b2e] shadow-sm overflow-hidden">
      {/* Toolbar */}
      <div className="px-4 sm:px-5 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0f1627] flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            Synchronized Side-by-Side Diff
          </span>
          <span className="text-slate-400">&bull;</span>
          <span>Hover highlighted entities for type &amp; validation metadata</span>
        </div>

        <button
          type="button"
          onClick={() => setWrapLines((w) => !w)}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${
            wrapLines
              ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
              : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700'
          }`}
        >
          <WrapText className="w-3.5 h-3.5" />
          Wrap Lines
        </button>
      </div>

      {!hasInput ? (
        <div className="py-16 px-6 text-center text-sm text-slate-500 dark:text-slate-400">
          Paste text, upload a <code className="font-mono">.txt</code>/<code className="font-mono">.csv</code> file, or load a sample dataset above to inspect live PII sanitization.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-200 dark:divide-slate-800">
          {/* Left Pane: Original Annotated */}
          <div className="flex flex-col min-w-0">
            <div className="px-4 py-2 bg-rose-500/5 dark:bg-rose-500/10 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300">
                <Eye className="w-3.5 h-3.5" />
                Original Input (PII Highlighted)
              </span>
              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                Read-Only Local Inspection
              </span>
            </div>

            <pre
              ref={leftPaneRef}
              onScroll={() => handleScroll('left')}
              className={`${preClass} bg-white dark:bg-slate-950/60 text-slate-800 dark:text-slate-200`}
            >
              {segments.map((seg, idx) => {
                if (seg.kind === 'text') {
                  return <React.Fragment key={idx}>{seg.originalText}</React.Fragment>;
                }
                const meta = PII_TYPES[seg.match.type];
                const tooltip = `Type: ${meta?.label || seg.match.type} | Validation: ${seg.match.validationMethod}`;
                return (
                  <mark
                    key={idx}
                    title={tooltip}
                    className={`px-1 py-0.5 rounded font-semibold cursor-help transition-all ${
                      meta?.highlightClass || 'bg-rose-500/20 text-rose-200'
                    }`}
                  >
                    {seg.originalText}
                  </mark>
                );
              })}
            </pre>
          </div>

          {/* Right Pane: Sanitized Output */}
          <div className="flex flex-col min-w-0">
            <div className="px-4 py-2 bg-emerald-500/5 dark:bg-emerald-500/10 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
                <Shield className="w-3.5 h-3.5" />
                Sanitized Output ({modeLabel})
              </span>
              <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
                Safe for AI / External Share
              </span>
            </div>

            <pre
              ref={rightPaneRef}
              onScroll={() => handleScroll('right')}
              className={`${preClass} bg-slate-50/70 dark:bg-slate-950/90 text-slate-800 dark:text-slate-200`}
            >
              {segments.map((seg, idx) => {
                if (seg.kind === 'text') {
                  return <React.Fragment key={idx}>{seg.sanitizedText}</React.Fragment>;
                }
                const meta = PII_TYPES[seg.match.type];
                const tooltip = `Redacted ${meta?.label || seg.match.type} | Method: ${seg.match.validationMethod}`;
                return (
                  <span
                    key={idx}
                    title={tooltip}
                    className="px-1.5 py-0.5 rounded bg-emerald-500/15 dark:bg-emerald-500/20 text-emerald-800 dark:text-emerald-300 ring-1 ring-emerald-500/40 font-semibold cursor-help"
                  >
                    {seg.sanitizedText}
                  </span>
                );
              })}
            </pre>
          </div>
        </div>
      )}
    </section>
  );
}
