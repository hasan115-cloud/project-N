import React from "react";
import { Download, RefreshCw, Shield } from "lucide-react";
import { getDownloadExtensionUrl } from "../api";

const PhishGuardFlagMark: React.FC<{ className?: string }> = ({ className }) => (
  <svg viewBox="0 0 32 32" className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="13" y="2" width="2.4" height="28" rx="1" fill="#fff" />
    <rect x="15.4" y="4" width="13.5" height="10.5" fill="#fff" />
  </svg>
);

interface HeaderProps {
  totalCount: number;
  onRefresh: () => void;
  isRefreshing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  totalCount,
  onRefresh,
  isRefreshing
}) => {
  return (
    <header className="h-16 bg-[#0e0e0e] border-b border-[#262626] px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30 shadow-md gap-3 overflow-hidden">
      {/* Brand */}
      <div className="flex items-center gap-3 min-w-0 shrink-0">
        <div className="w-9 h-9 rounded-lg bg-black border border-white/30 flex items-center justify-center p-1.5 shadow-inner shrink-0">
          <PhishGuardFlagMark className="w-full h-full" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold text-neutral-100 tracking-wide whitespace-nowrap">PhishGuard</h1>
            <span className="hidden md:inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 whitespace-nowrap">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shrink-0"></span>
              <span className="truncate">root@phishguard$ status ok</span>
              <span className="text-white shrink-0" title="System monitoring active">☠</span>
            </span>
          </div>
          <p className="text-xs text-neutral-400 font-medium truncate">Enterprise Security Management Console</p>
        </div>
      </div>

      {/* Status & Actions */}
      <div className="flex items-center gap-2 sm:gap-4 min-w-0 shrink-0">
        {/* Enrolled Endpoints Metric */}
        <div className="hidden md:flex items-center gap-2 bg-[#161616] border border-[#2a2a2a] px-3 py-1.5 rounded-lg text-xs shrink-0">
          <Shield className="w-3.5 h-3.5 text-[#ffffff]" />
          <span className="text-neutral-300 font-mono whitespace-nowrap">
            <strong className="text-neutral-100">{totalCount}</strong> Enrolled {totalCount === 1 ? "System" : "Systems"}
          </span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-2 text-neutral-300 hover:text-white bg-[#161616] hover:bg-[#232323] border border-[#2a2a2a] rounded-lg transition-colors shrink-0"
          title="Refresh Telemetry Data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? "animate-spin text-[#ffffff]" : ""}`} />
        </button>

        {/* Download Extension (.ZIP) Primary CTA */}
        <a
          href={getDownloadExtensionUrl()}
          download="phishguard-extension.zip"
          className="flex items-center gap-2 bg-white hover:bg-neutral-200 text-black text-xs font-bold px-3 sm:px-4 py-2 rounded-lg shadow-sm hover:shadow transition-all shrink-0 whitespace-nowrap"
        >
          <Download className="w-4 h-4" />
          <span className="hidden sm:inline">Download Extension (.ZIP)</span>
          <span className="sm:hidden">Extension</span>
        </a>
      </div>
    </header>
  );
};
