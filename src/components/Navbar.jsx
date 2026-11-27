import React from 'react';
import { ShieldCheck, Lock, Sun, Moon, WifiOff } from 'lucide-react';

export function Navbar({ theme, onToggleTheme }) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 dark:border-cyan-500/25 bg-white/90 dark:bg-[#040a14]/90 backdrop-blur-md">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-500/25 shrink-0 ring-1 ring-cyan-300/40">
              <ShieldCheck className="w-5 h-5 text-slate-950" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h1 className="text-lg sm:text-xl font-extrabold tracking-[0.12em] uppercase text-slate-900 dark:text-cyan-300">
                  Redact<span className="text-emerald-500 dark:text-emerald-400">Zero</span>
                </h1>
                <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider bg-slate-100 dark:bg-cyan-500/10 text-slate-600 dark:text-cyan-300 border border-slate-200 dark:border-cyan-500/30">
                  SOC-HUD v1.0
                </span>
              </div>
              <p className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate tracking-wide">
                Client-Side PII Sanitization &amp; Privacy Compliance
              </p>
            </div>
          </div>

          <nav
            aria-label="Security pipeline stages"
            className="hidden xl:flex items-center gap-5 ml-4 pl-5 border-l border-slate-200 dark:border-cyan-500/25 text-[11px] font-bold tracking-[0.2em] uppercase text-slate-500 dark:text-slate-400"
          >
            <span className="text-cyan-600 dark:text-cyan-400">Protect</span>
            <span className="text-cyan-600 dark:text-cyan-400">Detect</span>
            <span className="text-emerald-600 dark:text-emerald-400">Redact</span>
            <span className="text-cyan-600 dark:text-cyan-400">Verify</span>
          </nav>
        </div>

        <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
          <div
            title="All regex scanning, Luhn validation, FileReader parsing, and exports run strictly in browser memory. CSP connect-src is set to 'none'."
            className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/35 text-emerald-700 dark:text-emerald-300 text-xs font-medium shadow-sm shadow-emerald-500/10"
          >
            <span className="relative flex h-2 w-2 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            <Lock className="w-3.5 h-3.5 shrink-0 hidden sm:block" />
            <span className="hidden md:inline font-mono text-[11px]">
              100% Client-Side / Zero Network Egress
            </span>
            <span className="md:hidden inline-flex items-center gap-1 font-mono text-[11px]">
              <WifiOff className="w-3 h-3" /> Zero Egress
            </span>
          </div>

          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            className="p-2 rounded-lg border border-slate-200 dark:border-cyan-500/30 bg-slate-100/80 dark:bg-slate-900/90 hover:bg-slate-200 dark:hover:bg-cyan-500/10 text-slate-700 dark:text-cyan-300 transition-colors"
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-slate-700" />
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
