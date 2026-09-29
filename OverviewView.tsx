import React from "react";
import {
  AlertOctagon,
  CheckCircle2,
  Globe,
  Laptop,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TrendingUp
} from "lucide-react";
import { DashboardStats, EnrolledClient } from "../types";

interface OverviewViewProps {
  stats: DashboardStats;
  clients: EnrolledClient[];
  selectedSystem: string;
  onSelectSystem: (clientId: string) => void;
  onNavigateTab: (tab: any) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  stats,
  clients,
  selectedSystem,
  onSelectSystem,
  onNavigateTab
}) => {
  const {
    totalSystems,
    urlsMonitored,
    allowedUrls,
    phishingIntercepted,
    activeAlerts,
    breakdown,
    recentEvents,
    topThreatDomains
  } = stats;

  const totalEvaluated = breakdown.evaluated || 0;
  const safePercent = totalEvaluated > 0 ? ((breakdown.safe / totalEvaluated) * 100).toFixed(1) : "0.0";
  const suspiciousPercent = totalEvaluated > 0 ? ((breakdown.suspicious / totalEvaluated) * 100).toFixed(1) : "0.0";
  const phishingPercent = totalEvaluated > 0 ? ((breakdown.phishing / totalEvaluated) * 100).toFixed(1) : "0.0";

  return (
    <div className="space-y-6">
      {/* Top Banner / Heading */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div className="min-w-0">
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2 flex-wrap">
            <span>Security Overview</span>
            <span className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/5 text-emerald-400 whitespace-nowrap">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              monitoring::active
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Real-time event streams and defensive metrics collected from enrolled PhishGuard endpoints.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {/* System scope — shared with URL History so both views always
              describe the same server-side record set. */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Laptop className="w-3.5 h-3.5" />
            <select
              value={selectedSystem}
              onChange={e => onSelectSystem(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs px-2.5 py-2 rounded-lg focus:outline-none"
            >
              <option value="ALL">All Connected Systems</option>
              {clients.map(c => (
                <option key={c.id} value={c.id}>
                  {c.clientName} ({c.id.slice(-6)})
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() => onNavigateTab("install_extension")}
            className="text-xs bg-[#17253b] hover:bg-[#1f314d] text-[#ffffff] border border-[#ffffff]/30 font-medium px-3.5 py-2 rounded-lg transition-colors"
          >
            + Enroll New System
          </button>
        </div>
      </div>

      {/* 5 Core Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {/* 1. Total Enrolled Systems */}
        <div
          onClick={() => onNavigateTab("enrolled_systems")}
          className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl cursor-pointer hover:border-[#ffffff]/50 transition-colors"
        >
          <div className="flex items-center justify-between text-neutral-400 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Total Enrolled</span>
            <Laptop className="w-4 h-4 text-[#ffffff]" />
          </div>
          <div className="text-2xl font-bold text-neutral-100 font-mono">{totalSystems}</div>
          <div className="text-[11px] text-neutral-500 mt-1">Registered clients</div>
        </div>

        {/* 2. URLs Monitored */}
        <div
          onClick={() => onNavigateTab("url_history")}
          className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl cursor-pointer hover:border-[#ffffff]/50 transition-colors"
        >
          <div className="flex items-center justify-between text-neutral-400 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">URLs Monitored</span>
            <Globe className="w-4 h-4 text-[#ffffff]" />
          </div>
          <div className="text-2xl font-bold text-[#ffffff] font-mono">{urlsMonitored}</div>
          <div className="text-[11px] text-neutral-500 mt-1">
            {selectedSystem === "ALL" ? "All systems" : "Selected system"}
          </div>
        </div>

        {/* 3. Allowed URLs */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl">
          <div className="flex items-center justify-between text-neutral-400 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Allowed URLs</span>
            <CheckCircle2 className="w-4 h-4 text-teal-400" />
          </div>
          <div className="text-2xl font-bold text-teal-400 font-mono">{allowedUrls}</div>
          <div className="text-[11px] text-neutral-500 mt-1">Legitimate traffic</div>
        </div>

        {/* 4. Phishing Intercepted */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl">
          <div className="flex items-center justify-between text-neutral-400 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Intercepted</span>
            <AlertOctagon className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{phishingIntercepted}</div>
          <div className="text-[11px] text-neutral-500 mt-1">Blocked destinations</div>
        </div>

        {/* 5. Active Security Alerts */}
        <div
          onClick={() => onNavigateTab("threat_alerts")}
          className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl cursor-pointer hover:border-amber-500/50 transition-colors"
        >
          <div className="flex items-center justify-between text-neutral-400 mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider">Active Alerts</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono">{activeAlerts}</div>
          <div className="text-[11px] text-neutral-500 mt-1">Unresolved threats</div>
        </div>
      </div>

      {/* Middle Row: Classification Breakdown & Top Threat Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Classification Breakdown */}
        <div className="lg:col-span-2 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-neutral-100">URL Classification Breakdown</h3>
              <p className="text-xs text-neutral-400">Distribution of all processed real-time telemetries</p>
            </div>
            <span className="text-xs font-mono text-neutral-400">
              Total: {totalEvaluated} = {breakdown.safe} safe + {breakdown.suspicious} suspicious + {breakdown.phishing} phishing
            </span>
          </div>

          {totalEvaluated === 0 ? (
            <div className="py-10 text-center text-neutral-500 text-xs">
              <Shield className="w-8 h-8 mx-auto mb-2 text-neutral-600 opacity-50" />
              No URL events evaluated yet. Install the PhishGuard extension to start receiving live telemetry.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Progress bar */}
              <div className="w-full h-3 bg-[#161616] rounded-full overflow-hidden flex">
                <div style={{ width: `${safePercent}%` }} className="bg-emerald-500 h-full" title={`Safe: ${safePercent}%`}></div>
                <div style={{ width: `${suspiciousPercent}%` }} className="bg-amber-500 h-full" title={`Suspicious: ${suspiciousPercent}%`}></div>
                <div style={{ width: `${phishingPercent}%` }} className="bg-rose-500 h-full" title={`Phishing: ${phishingPercent}%`}></div>
              </div>

              {/* 4 Classification Metric Chips */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                <div className="bg-[#161616] border border-[#262626] p-3 rounded-lg">
                  <div className="text-neutral-400 text-[11px] font-medium">URLs Evaluated</div>
                  <div className="text-lg font-bold text-neutral-200 font-mono mt-0.5">{breakdown.evaluated}</div>
                  <div className="text-[10px] text-neutral-500 mt-1">100% telemetry</div>
                </div>

                <div className="bg-[#161616] border border-[#262626] p-3 rounded-lg">
                  <div className="text-emerald-400 text-[11px] font-medium">Safe URLs</div>
                  <div className="text-lg font-bold text-emerald-400 font-mono mt-0.5">{breakdown.safe}</div>
                  <div className="text-[10px] text-neutral-500 mt-1">{safePercent}% ratio</div>
                </div>

                <div className="bg-[#161616] border border-[#262626] p-3 rounded-lg">
                  <div className="text-amber-400 text-[11px] font-medium">Suspicious URLs</div>
                  <div className="text-lg font-bold text-amber-400 font-mono mt-0.5">{breakdown.suspicious}</div>
                  <div className="text-[10px] text-neutral-500 mt-1">{suspiciousPercent}% ratio</div>
                </div>

                <div className="bg-[#161616] border border-[#262626] p-3 rounded-lg">
                  <div className="text-rose-400 text-[11px] font-medium">Phishing URLs</div>
                  <div className="text-lg font-bold text-rose-400 font-mono mt-0.5">{breakdown.phishing}</div>
                  <div className="text-[10px] text-neutral-500 mt-1">{phishingPercent}% ratio</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Top Blocked Threat Domains */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-neutral-100 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-rose-400" />
              <span>Top Blocked Threat Domains</span>
            </h3>
            <p className="text-xs text-neutral-400 mt-0.5">Calculated from actual intercepted threat alerts</p>

            <div className="mt-4 space-y-2">
              {topThreatDomains.length === 0 ? (
                <div className="py-8 text-center text-neutral-500 text-xs">
                  No phishing domains blocked yet. Zero threats currently recorded in database.
                </div>
              ) : (
                topThreatDomains.map((item, idx) => (
                  <div
                    key={item.domain}
                    className="flex items-center justify-between p-2.5 bg-[#161616] border border-[#262626] rounded-lg text-xs"
                  >
                    <div className="flex items-center gap-2 overflow-hidden mr-2">
                      <span className="w-5 h-5 rounded bg-rose-500/20 text-rose-400 font-mono font-bold flex items-center justify-center text-[10px]">
                        {idx + 1}
                      </span>
                      <span className="font-mono text-neutral-200 truncate">{item.domain}</span>
                    </div>
                    <span className="bg-rose-500/15 text-rose-400 font-mono font-bold px-2 py-0.5 rounded text-[10px] shrink-0 border border-rose-500/30">
                      {item.count} hits
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          <button
            onClick={() => onNavigateTab("threat_alerts")}
            className="w-full text-center text-xs text-[#ffffff] hover:text-[#d4d4d4] pt-4 font-medium"
          >
            View Threat Alerts Center →
          </button>
        </div>
      </div>

      {/* Bottom Table: Recent Real-Time Navigation Events */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-neutral-100">Recent Real-Time Navigation Events</h3>
            <p className="text-xs text-neutral-400">Live stream of extension evaluations across enrolled systems</p>
          </div>
          <button
            onClick={() => onNavigateTab("url_history")}
            className="text-xs text-[#ffffff] hover:underline font-medium"
          >
            View Full URL History →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-neutral-300">
            <thead className="bg-[#161616] text-neutral-400 font-semibold border-b border-[#262626]">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">System / Client</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Destination Domain</th>
                <th className="py-2.5 px-3">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {recentEvents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-neutral-500 text-xs">
                    No real-time navigation events recorded yet. Connect an extension to begin streaming live security events.
                  </td>
                </tr>
              ) : (
                recentEvents.map(evt => (
                  <tr key={evt.id} className="hover:bg-[#161616]/60 transition-colors">
                    <td className="py-2 px-3 text-neutral-400 font-mono whitespace-nowrap text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td className="py-2 px-3 font-medium text-neutral-200">
                      <div className="flex items-center gap-1.5">
                        <Laptop className="w-3.5 h-3.5 text-neutral-400" />
                        <span>{evt.clientName}</span>
                      </div>
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          evt.classification === "PHISHING"
                            ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                            : evt.classification === "SUSPICIOUS"
                            ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                            : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {evt.classification === "PHISHING" ? "🛑" : evt.classification === "SUSPICIOUS" ? "⚠️" : "✅"}
                        {evt.classification}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-neutral-300 max-w-xs truncate" title={evt.url}>
                      <div className="truncate">{evt.domain || evt.url}</div>
                      {evt.ruleTriggered && (
                        <span className="inline-flex items-center gap-1 mt-0.5 text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-white/10 text-white border border-white/30">
                          {evt.ruleType === "WHITELIST" ? "Whitelist Rule Triggered" : evt.ruleType === "PHISHING" ? "Blacklist Rule Triggered" : "Rule Triggered"}
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`font-semibold text-[11px] ${
                          evt.verdict === "BLOCKED"
                            ? "text-rose-400"
                            : evt.verdict === "WARNING"
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }`}
                      >
                        {evt.verdict}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
