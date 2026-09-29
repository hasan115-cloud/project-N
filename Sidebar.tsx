import React from "react";
import {
  Activity,
  AlertTriangle,
  DownloadCloud,
  FileText,
  History,
  Laptop,
  LayoutDashboard,
  ShieldCheck
} from "lucide-react";
import { NavigationTab } from "../types";

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  activeAlertsCount: number;
  enrolledSystemsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  activeAlertsCount,
  enrolledSystemsCount
}) => {
  return (
    <aside className="w-64 bg-[#000000] border-r border-[#262626] flex flex-col justify-between shrink-0 select-none min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-6">
        {/* Group 1: Monitoring */}
        <div>
          <div className="px-3 text-[11px] font-semibold text-neutral-500 uppercase tracking-wider mb-2">
            Monitoring
          </div>
          <div className="space-y-1">
            <button
              onClick={() => onSelectTab("overview")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "overview"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Overview Dashboard</span>
            </button>

            <button
              onClick={() => onSelectTab("enrolled_systems")}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "enrolled_systems"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <div className="flex items-center gap-3">
                <Laptop className="w-4 h-4" />
                <span>Enrolled Systems</span>
              </div>
              {enrolledSystemsCount > 0 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[#1f1f1f] text-[#ffffff] font-mono font-bold">
                  {enrolledSystemsCount}
                </span>
              )}
            </button>

            <button
              onClick={() => onSelectTab("url_history")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "url_history"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <History className="w-4 h-4" />
              <span>URL History</span>
            </button>
          </div>
        </div>

        {/* Group 2: Security */}
        <div>
          <div className="px-3 text-[11px] font-semibold text-neutral-500 uppercase tracking-wider mb-2">
            Security
          </div>
          <div className="space-y-1">
            <button
              onClick={() => onSelectTab("security_rules")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "security_rules"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Security Rules & Policy</span>
            </button>

            <button
              onClick={() => onSelectTab("threat_alerts")}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "threat_alerts"
                  ? "bg-[#232323] text-[#ff6b7a] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-4 h-4" />
                <span>Threat Alerts</span>
              </div>
              {activeAlertsCount > 0 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-rose-500/20 text-rose-400 font-mono font-bold border border-rose-500/30">
                  {activeAlertsCount}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Group 3: Reports */}
        <div>
          <div className="px-3 text-[11px] font-semibold text-neutral-500 uppercase tracking-wider mb-2">
            Reports
          </div>
          <div className="space-y-1">
            <button
              onClick={() => onSelectTab("install_extension")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "install_extension"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <DownloadCloud className="w-4 h-4" />
              <span>Install Extension</span>
            </button>

            <button
              onClick={() => onSelectTab("reports")}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                currentTab === "reports"
                  ? "bg-[#232323] text-[#ffffff] shadow-sm"
                  : "text-neutral-300 hover:bg-[#161616] hover:text-white"
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Reports & Analytics</span>
            </button>
          </div>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-[#262626] text-[11px] text-neutral-500">
        <div className="flex items-center justify-between">
          <span>Agent Model v1.4</span>
          <span className="text-emerald-400 font-mono">ACTIVE</span>
        </div>
        <div className="mt-1 text-[10px] text-neutral-600 truncate">
          Client–Server Protocol MV3
        </div>
      </div>
    </aside>
  );
};
