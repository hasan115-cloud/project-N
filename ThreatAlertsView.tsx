import React, { useCallback, useEffect, useRef, useState } from "react";
import { AlertOctagon, CheckCircle, Clock, ExternalLink, Filter, Laptop, RefreshCw, ShieldAlert } from "lucide-react";
import { EnrolledClient, ThreatAlert } from "../types";
import { errMsg, fetchThreatAlerts, updateAlertStatus } from "../api";

interface ThreatAlertsViewProps {
  clients: EnrolledClient[];
  onAlertUpdated: () => void;
}

export const ThreatAlertsView: React.FC<ThreatAlertsViewProps> = ({ clients, onAlertUpdated }) => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedClient, setSelectedClient] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const scopeRef = useRef(selectedClient);
  scopeRef.current = selectedClient;
  const seq = useRef(0);

  const loadAlerts = useCallback(async (silent = false) => {
    const id = ++seq.current;
    if (!silent) setIsLoading(true);
    try {
      const data = await fetchThreatAlerts(scopeRef.current);
      if (id !== seq.current) return;
      setAlerts(data);
      setHasLoaded(true);
      setLoadError(null);
    } catch (e) {
      if (id !== seq.current) return;
      console.error("Failed to load threat alerts", e);
      setLoadError(errMsg(e, "Failed to load threat alerts."));   // existing alerts stay on screen
    } finally {
      if (id === seq.current) setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    setAlerts([]);
    setHasLoaded(false);
    loadAlerts(false);
    const timer = setInterval(() => { if (document.visibilityState === "visible") loadAlerts(true); }, 10_000);
    return () => clearInterval(timer);
  }, [selectedClient, loadAlerts]);

  const handleStatusChange = async (id: string, newStatus: "ACKNOWLEDGED" | "RESOLVED") => {
    try {
      await updateAlertStatus(id, newStatus);
      await loadAlerts(true);
      onAlertUpdated();
    } catch (e) {
      setLoadError(errMsg(e, "Failed to update alert status."));
    }
  };

  const filteredAlerts = alerts.filter(a => {
    if (statusFilter !== "ALL" && a.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2">
            <span>Threat Detection & Alert Center</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
              {alerts.filter(a => a.status === "ACTIVE").length} Active Threats
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Real-time phishing interceptions reported by PhishGuard browser endpoints in your environment.
          </p>
        </div>

        <button
          onClick={() => loadAlerts(false)}
          disabled={isLoading}
          className="flex items-center gap-2 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white px-3.5 py-2 rounded-lg border border-[#2a2a2a] transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-[#ffffff]" : ""}`} />
          <span>Refresh Alerts</span>
        </button>
      </div>

      {/* Filter bar */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap items-center gap-3">
          {/* Client Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Laptop className="w-3.5 h-3.5" />
            <select
              value={selectedClient}
              onChange={e => setSelectedClient(e.target.value)}
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

          {/* Status Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs px-2.5 py-2 rounded-lg focus:outline-none"
            >
              <option value="ALL">All Threat Statuses</option>
              <option value="ACTIVE">Active Threats</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>

        <div className="text-xs font-mono text-neutral-400">
          Showing {filteredAlerts.length} of {alerts.length} Total Alerts
        </div>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {loadError && (
          <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs px-4 py-2.5 rounded-lg flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            <span>{loadError}{hasLoaded ? " — showing the last alerts received." : ""}</span>
          </div>
        )}
        {!hasLoaded && loadError ? null : !hasLoaded ? (
          <div className="p-12 text-center text-neutral-400 text-xs bg-[#0e0e0e] border border-[#262626] rounded-xl">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-[#ffffff] mb-2" />
            Fetching active security alerts...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="p-12 text-center text-neutral-500 bg-[#0e0e0e] border border-[#262626] rounded-xl">
            <ShieldAlert className="w-10 h-10 mx-auto mb-2 opacity-40 text-neutral-600" />
            <div className="text-sm font-medium text-neutral-400">No Phishing Threats Found</div>
            <p className="text-xs text-neutral-500 max-w-sm mx-auto mt-1">
              Zero threat alerts recorded for this selection. When a user browsing on an enrolled system encounters a phishing site, it is blocked and raised here automatically.
            </p>
          </div>
        ) : (
          filteredAlerts.map(alert => (
            <div
              key={alert.id}
              className={`p-4 rounded-xl border transition-all ${
                alert.status === "ACTIVE"
                  ? "bg-[#14121d] border-rose-500/40 shadow-lg shadow-rose-950/20"
                  : alert.status === "ACKNOWLEDGED"
                  ? "bg-[#141824] border-amber-500/30"
                  : "bg-[#0e0e0e] border-[#262626] opacity-75"
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg shrink-0 mt-0.5 ${alert.status === "ACTIVE" ? "bg-rose-500/20 text-rose-400" : "bg-neutral-800 text-neutral-400"}`}>
                    <AlertOctagon className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-neutral-100 font-mono">{alert.domain}</span>
                      <span
                        className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                          alert.status === "ACTIVE"
                            ? "bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse"
                            : alert.status === "ACKNOWLEDGED"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : "bg-neutral-700/30 text-neutral-400 border border-neutral-700/50"
                        }`}
                      >
                        {alert.status}
                      </span>
                    </div>

                    <div className="text-xs text-neutral-400 font-mono mt-1 break-all">
                      Target URL: {alert.url}
                    </div>
                    {alert.matchedPattern && (
                      <div className="text-[11px] text-neutral-300 mt-1">
                        Rule Triggered · Matched Rule: <span className="font-mono text-white">{alert.matchedPattern}</span>
                        {" · "}Type: {alert.ruleType === "WHITELIST" ? "Whitelist" : "Phishing / Blacklist"}
                        {" · "}Action: <span className="text-rose-400 font-bold">{(alert.action || "BLOCKED") === "BLOCKED" ? "Blocked" : alert.action}</span>
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-neutral-400 mt-2">
                      <div className="flex items-center gap-1">
                        <Laptop className="w-3.5 h-3.5 text-neutral-500" />
                        <span className="text-neutral-300 font-medium">{alert.clientName}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-neutral-500" />
                        <span>{new Date(alert.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span>Threat Score:</span>
                        <strong className="text-rose-400 font-mono">{(alert.score * 100).toFixed(0)}%</strong>
                      </div>
                    </div>

                    {alert.reasons && alert.reasons.length > 0 && (
                      <div className="mt-2.5 flex flex-wrap gap-1.5">
                        {alert.reasons.map((r, i) => (
                          <span key={i} className="text-[10px] bg-[#1a233a] border border-[#263757] text-neutral-300 px-2 py-0.5 rounded">
                            {r}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Status Action Buttons */}
                <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                  {alert.status === "ACTIVE" && (
                    <button
                      onClick={() => handleStatusChange(alert.id, "ACKNOWLEDGED")}
                      className="text-xs bg-amber-500/15 hover:bg-amber-500/25 text-amber-400 border border-amber-500/30 px-3 py-1.5 rounded-lg font-medium transition-colors"
                    >
                      Acknowledge
                    </button>
                  )}
                  {alert.status !== "RESOLVED" && (
                    <button
                      onClick={() => handleStatusChange(alert.id, "RESOLVED")}
                      className="text-xs bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 px-3 py-1.5 rounded-lg font-medium transition-colors"
                    >
                      Mark Resolved
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
