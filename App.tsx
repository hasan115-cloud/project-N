import React, { useCallback, useEffect, useRef, useState } from "react";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { OverviewView } from "./components/OverviewView";
import { EnrolledSystemsView } from "./components/EnrolledSystemsView";
import { UrlHistoryView } from "./components/UrlHistoryView";
import { SecurityRulesView } from "./components/SecurityRulesView";
import { ThreatAlertsView } from "./components/ThreatAlertsView";
import { InstallExtensionView } from "./components/InstallExtensionView";
import { ReportsView } from "./components/ReportsView";
import { DashboardStats, EnrolledClient, NavigationTab } from "./types";
import { errMsg, fetchClients, fetchStats, isAbort } from "./api";
import { AlertTriangle, RefreshCw } from "lucide-react";

const POLL_MS = 10_000;

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavigationTab>("overview");

  // `null` means "not loaded yet" — NOT "zero". Rendering zeros before the first
  // response (the old EMPTY_STATS) made a slow/failed load look like an empty
  // database. Once real data has arrived it is only ever replaced by newer real
  // data; a failed refresh keeps showing the last good data plus an error banner.
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [clients, setClients] = useState<EnrolledClient[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // The selected system is owned HERE so Overview and URL History always
  // describe the same scope.
  const [selectedSystem, setSelectedSystem] = useState("ALL");

  // Only the newest request may write state; older in-flight ones are aborted.
  const latestRequest = useRef(0);
  const inflight = useRef<AbortController | null>(null);
  const scopeRef = useRef(selectedSystem);
  scopeRef.current = selectedSystem;

  const loadDashboardData = useCallback(async (silent = false) => {
    const requestId = ++latestRequest.current;
    inflight.current?.abort();
    const ctrl = new AbortController();
    inflight.current = ctrl;
    if (!silent) setIsRefreshing(true);
    try {
      const [newStats, newClients] = await Promise.all([
        fetchStats(scopeRef.current, ctrl.signal),
        fetchClients(ctrl.signal)
      ]);
      if (requestId !== latestRequest.current) return;
      setStats(newStats);
      setClients(newClients);
      setLoadError(null);
    } catch (e) {
      if (isAbort(e) || requestId !== latestRequest.current) return;
      console.error("Telemetry sync error:", e);
      setLoadError(errMsg(e, "Failed to load data from the server"));
    } finally {
      if (requestId === latestRequest.current) setIsRefreshing(false);
    }
  }, []);

  // Load on mount and whenever the scope changes; poll while the tab is visible.
  useEffect(() => {
    loadDashboardData(false);
    const tick = () => { if (document.visibilityState === "visible") loadDashboardData(true); };
    const timer = setInterval(tick, POLL_MS);
    const onVisible = () => { if (document.visibilityState === "visible") loadDashboardData(true); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
      inflight.current?.abort();
    };
  }, [selectedSystem, loadDashboardData]);

  const clientList = clients ?? [];

  return (
    <div className="min-h-screen bg-[#000000] text-neutral-100 flex flex-col font-sans">
      {/* SOC Top Header */}
      <Header
        totalCount={clientList.length}
        onRefresh={() => loadDashboardData(false)}
        isRefreshing={isRefreshing}
      />

      {/* Main Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          activeAlertsCount={stats?.activeAlerts ?? 0}
          enrolledSystemsCount={clientList.length}
        />

        {/* Dynamic Tab View Container */}
        <main className="flex-1 p-6 lg:p-8 overflow-y-auto bg-[#000000]">
          <div className="max-w-7xl mx-auto">
            {loadError && (
              <div className="mb-4 flex items-center gap-2 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs px-4 py-2.5 rounded-lg">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span className="flex-1">
                  {loadError}
                  {stats ? " — showing the last data received." : ""}
                </span>
                <button onClick={() => loadDashboardData(false)} className="underline hover:text-rose-300 shrink-0">Retry</button>
              </div>
            )}

            {currentTab === "overview" && !stats && (
              <div className="p-12 text-center text-neutral-400 text-xs bg-[#0e0e0e] border border-[#262626] rounded-xl">
                <RefreshCw className={`w-6 h-6 mx-auto mb-2 text-white ${loadError ? "" : "animate-spin"}`} />
                {loadError ? "Could not load dashboard data." : "Loading dashboard data from the database…"}
              </div>
            )}

            {currentTab === "overview" && stats && (
              <OverviewView
                stats={stats}
                clients={clientList}
                selectedSystem={selectedSystem}
                onSelectSystem={setSelectedSystem}
                onNavigateTab={setCurrentTab}
              />
            )}

            {currentTab === "enrolled_systems" && (
              <EnrolledSystemsView
                clients={clientList}
                onNavigateTab={setCurrentTab}
                onRefresh={() => loadDashboardData(false)}
              />
            )}

            {currentTab === "url_history" && (
              <UrlHistoryView
                clients={clientList}
                selectedClient={selectedSystem}
                onSelectClient={setSelectedSystem}
              />
            )}

            {currentTab === "security_rules" && (
              <SecurityRulesView />
            )}

            {currentTab === "threat_alerts" && (
              <ThreatAlertsView
                clients={clientList}
                onAlertUpdated={() => loadDashboardData(true)}
              />
            )}

            {currentTab === "install_extension" && (
              <InstallExtensionView />
            )}

            {currentTab === "reports" && (
              <ReportsView clients={clientList} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
