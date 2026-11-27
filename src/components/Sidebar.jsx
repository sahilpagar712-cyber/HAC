import React from 'react';
import {
  Home,
  Activity,
  Search,
  Shield,
  Lock,
  Settings,
  Info,
  ShieldCheck,
  Image as ImageIcon,
} from 'lucide-react';

export const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: Home },
  { id: 'monitor', label: 'Threat Monitor', icon: Activity },
  { id: 'scan', label: 'Scan', icon: Search },
  { id: 'image-scanner', label: 'Image Scanner', icon: ImageIcon },
  { id: 'firewall', label: 'Firewall', icon: Shield },
  { id: 'privacy', label: 'Privacy Guard', icon: Lock },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'about', label: 'About', icon: Info },
];

export function Sidebar({
  activeTab,
  onSelectTab,
  totalDetected,
  activeRedactedCount,
  isScanning,
  mobileOpen,
  onCloseMobile,
  backendOnline,
  currentUser,
}) {
  const isAllClean = totalDetected === 0 || activeRedactedCount === totalDetected;

  return (
    <>
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
        />
      )}

      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 w-64 shrink-0 flex flex-col justify-between border-r border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0e1525] transition-transform duration-200 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div>
          {/* Brand Header */}
          <div className="h-16 px-5 flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center shrink-0">
              <ShieldCheck className="w-5 h-5 text-blue-500 dark:text-[#5b93ff]" />
            </div>
            <div className="min-w-0">
              <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-white">
                RedactZero
              </span>
            </div>
          </div>

          {/* Navigation Menu */}
          <nav aria-label="Main navigation" className="px-3 py-3 space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    onSelectTab(item.id);
                    onCloseMobile?.();
                  }}
                  className={`w-full flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-blue-500/15 text-blue-600 dark:text-white border border-blue-500/25 shadow-sm'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <span className="flex items-center gap-3">
                    <Icon
                      className={`w-4 h-4 ${
                        isActive
                          ? 'text-blue-500 dark:text-[#5b93ff]'
                          : 'text-slate-400 dark:text-slate-400'
                      }`}
                    />
                    <span>{item.label}</span>
                  </span>

                  {item.id === 'monitor' && totalDetected > 0 && (
                    <span className="px-1.5 py-0.5 rounded-md text-[10px] font-mono font-semibold bg-rose-500/15 text-rose-500 dark:text-rose-400">
                      {totalDetected}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom-left System Status Card */}
        <div className="p-4">
          <button
            type="button"
            onClick={() => onSelectTab('firewall')}
            className="w-full text-left rounded-2xl border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-[#121b2f] p-3.5 hover:border-emerald-500/40 transition-colors"
          >
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span
                className={`w-2 h-2 rounded-full ${
                  isScanning
                    ? 'bg-blue-400 animate-ping'
                    : isAllClean
                      ? 'bg-emerald-400'
                      : 'bg-amber-400'
                }`}
              />
              <span>System Status</span>
              {backendOnline && (
                <span className="ml-auto text-[10px] font-mono text-emerald-500">API OK</span>
              )}
            </div>
            <div
              className={`mt-1 text-sm font-semibold ${
                isAllClean
                  ? 'text-emerald-600 dark:text-emerald-400'
                  : 'text-amber-600 dark:text-amber-400'
              }`}
            >
              {isScanning
                ? 'Scanning Buffer...'
                : totalDetected === 0
                  ? 'All Good'
                  : `${activeRedactedCount}/${totalDetected} Masked`}
            </div>
            {currentUser && (
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                Session: {currentUser.username}
              </div>
            )}

            {/* Smooth green wave sparkline */}
            <svg
              viewBox="0 0 180 38"
              className="w-full h-9 mt-2 overflow-visible"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="sysWaveFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                </linearGradient>
              </defs>
              <path
                d="M0,28 C20,26 30,18 48,22 C66,26 78,12 96,17 C114,22 126,30 144,18 C158,9 170,12 180,15 L180,38 L0,38 Z"
                fill="url(#sysWaveFill)"
              />
              <path
                d="M0,28 C20,26 30,18 48,22 C66,26 78,12 96,17 C114,22 126,30 144,18 C158,9 170,12 180,15"
                fill="none"
                stroke="#10b981"
                strokeWidth="1.8"
              />
            </svg>
          </button>
        </div>
      </aside>
    </>
  );
}
