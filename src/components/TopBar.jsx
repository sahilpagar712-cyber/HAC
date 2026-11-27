import React, { useMemo, useState } from 'react';
import {
  Search,
  Bell,
  Sun,
  Moon,
  Lock,
  Menu,
  X,
  ArrowRight,
  LogIn,
  LogOut,
  User,
} from 'lucide-react';
import { PII_TYPES } from '../engine/piiDetector.js';

export function TopBar({
  searchQuery,
  onSearchChange,
  theme,
  onToggleTheme,
  matches,
  alerts,
  onNavigate,
  onOpenMobileMenu,
  currentUser,
  onOpenAuthModal,
  onLogout,
  backendOnline,
}) {
  const [bellOpen, setBellOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const searchResults = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [];

    const results = [];

    // Search quick navigation pages
    const pages = [
      { id: 'dashboard', label: 'Dashboard Overview', kind: 'View' },
      { id: 'monitor', label: 'Threat Monitor & Entities', kind: 'View' },
      { id: 'scan', label: 'Scan & Sanitize Diff Workbench', kind: 'View' },
      { id: 'image-scanner', label: 'Image Security Scanner & History', kind: 'View' },
      { id: 'firewall', label: 'Firewall / Zero-Egress Guard', kind: 'View' },
      { id: 'privacy', label: 'Privacy Guard & Pseudonym Vault', kind: 'View' },
      { id: 'settings', label: 'Settings & Detection Rules', kind: 'View' },
    ];
    for (const p of pages) {
      if (p.label.toLowerCase().includes(q)) {
        results.push({
          key: `page-${p.id}`,
          title: p.label,
          subtitle: p.kind,
          tab: p.id,
        });
      }
    }

    // Search detected PII matches (type, validation method, or masked preview)
    for (const m of matches.slice(0, 40)) {
      const meta = PII_TYPES[m.type];
      const hay = `${m.type} ${meta?.label || ''} ${m.value} ${m.validationMethod}`.toLowerCase();
      if (hay.includes(q)) {
        results.push({
          key: `match-${m.start}-${m.end}`,
          title: `${meta?.shortLabel || m.type}: ${m.value}`,
          subtitle: `${m.validationMethod} (offset ${m.start})`,
          tab: 'scan',
        });
      }
      if (results.length >= 7) break;
    }

    return results;
  }, [searchQuery, matches]);

  return (
    <header className="h-16 px-4 sm:px-6 border-b border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-[#0b1120]/90 backdrop-blur-md flex items-center justify-between gap-4 sticky top-0 z-20">
      <div className="flex items-center gap-3 flex-1 max-w-2xl">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 lg:hidden"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Functional Search Bar */}
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search anything... (PII type, email, IP, Luhn, settings)"
            className="w-full h-10 pl-10 pr-9 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#11192c] text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500/60"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              aria-label="Clear search"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded-md text-slate-400 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Live Search Results Dropdown */}
          {searchQuery.trim() && (
            <div className="absolute left-0 right-0 mt-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#11192c] shadow-2xl overflow-hidden z-40">
              {searchResults.length === 0 ? (
                <div className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                  No matches found for &ldquo;{searchQuery}&rdquo;.
                </div>
              ) : (
                <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-72 overflow-auto">
                  {searchResults.map((res) => (
                    <button
                      key={res.key}
                      type="button"
                      onClick={() => {
                        onNavigate(res.tab);
                        onSearchChange('');
                      }}
                      className="w-full px-4 py-2.5 text-left flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-slate-900 dark:text-slate-100 truncate font-mono">
                          {res.title}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                          {res.subtitle}
                        </div>
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right Status & Controls */}
      <div className="flex items-center gap-2.5 shrink-0">
        <div
          title={
            backendOnline
              ? 'PII detection runs locally; API connected on same origin (/api).'
              : 'All processing runs locally in browser memory.'
          }
          className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-700 dark:text-emerald-400 text-xs font-medium"
        >
          <Lock className="w-3.5 h-3.5" />
          <span>
            {backendOnline ? 'Zero-Egress + Local API Active' : '100% Client-Side / Zero Network Egress'}
          </span>
        </div>

        {/* Notifications Bell */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setBellOpen((o) => !o)}
            aria-label="Toggle alerts popover"
            className="relative p-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#11192c] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500" />
            )}
          </button>

          {bellOpen && (
            <div className="absolute right-0 mt-2 w-80 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#121b2f] shadow-2xl p-3 z-50">
              <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-200 dark:border-slate-800">
                <span className="text-xs font-semibold text-slate-900 dark:text-white">
                  Compliance Alerts
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setBellOpen(false);
                    onNavigate('monitor');
                  }}
                  className="text-[11px] text-blue-500 dark:text-[#5b93ff] hover:underline"
                >
                  Open Monitor
                </button>
              </div>
              <div className="space-y-2 max-h-60 overflow-auto">
                {alerts.map((alert) => (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => {
                      setBellOpen(false);
                      onNavigate(alert.targetTab || 'monitor');
                    }}
                    className="w-full text-left p-2 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                  >
                    <div className="text-xs font-medium text-slate-800 dark:text-slate-100">
                      {alert.title}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400">
                      {alert.detail}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Theme Toggle */}
        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#11192c] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-slate-700" />
          )}
        </button>

        {/* User Avatar / Auth Menu */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setUserMenuOpen((o) => !o)}
            title={currentUser ? `Signed in as ${currentUser.username}` : 'Sign in / Register'}
            className="w-9 h-9 rounded-full bg-slate-200 dark:bg-[#1a243b] border border-slate-300 dark:border-slate-700 flex items-center justify-center text-xs font-semibold text-slate-700 dark:text-slate-200 hover:border-[#5b93ff] transition-colors"
          >
            {currentUser ? currentUser.username.slice(0, 2).toUpperCase() : 'RZ'}
          </button>

          {userMenuOpen && (
            <div className="absolute right-0 mt-2 w-56 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#121b2f] shadow-2xl p-2.5 z-50">
              {currentUser ? (
                <div className="space-y-2">
                  <div className="px-2.5 py-2 border-b border-slate-200 dark:border-slate-800">
                    <div className="text-xs font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-[#5b93ff]" />
                      {currentUser.username}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                      {currentUser.email}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setUserMenuOpen(false);
                      onLogout?.();
                    }}
                    className="w-full flex items-center gap-2 px-2.5 py-2 rounded-xl text-xs font-medium text-rose-500 hover:bg-rose-500/10 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    setUserMenuOpen(false);
                    onOpenAuthModal?.();
                  }}
                  className="w-full flex items-center gap-2 px-2.5 py-2 rounded-xl text-xs font-semibold text-[#5b93ff] hover:bg-blue-500/10 transition-colors"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  Sign In / Register
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
