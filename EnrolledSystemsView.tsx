import React, { useState } from "react";
import {
  AlertOctagon,
  Clock,
  ExternalLink,
  Globe,
  Info,
  Laptop,
  Monitor,
  Search,
  Shield,
  Trash2,
  X
} from "lucide-react";
import { EnrolledClient, ThreatAlert, UrlEvent } from "../types";
import { deleteClient, fetchClientDetails } from "../api";

interface EnrolledSystemsViewProps {
  clients: EnrolledClient[];
  onNavigateTab: (tab: any) => void;
  onRefresh?: () => void;
}

export const EnrolledSystemsView: React.FC<EnrolledSystemsViewProps> = ({ clients, onNavigateTab, onRefresh }) => {
  const [selectedClient, setSelectedClient] = useState<EnrolledClient | null>(null);
  const [clientEvents, setClientEvents] = useState<UrlEvent[]>([]);
  const [clientEventsTotal, setClientEventsTotal] = useState(0);
  const [clientAlerts, setClientAlerts] = useState<ThreatAlert[]>([]);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [search, setSearch] = useState("");

  const filteredClients = clients.filter(c =>
    c.clientName.toLowerCase().includes(search.toLowerCase()) ||
    c.id.toLowerCase().includes(search.toLowerCase()) ||
    c.os.toLowerCase().includes(search.toLowerCase()) ||
    c.browser.toLowerCase().includes(search.toLowerCase()) ||
    c.ip.toLowerCase().includes(search.toLowerCase())
  );

  const handleDeleteClient = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to permanently unenroll and remove ${name} (${id}) from the database?`)) {
      return;
    }
    setIsDeleting(true);
    try {
      await deleteClient(id);
      if (selectedClient?.id === id) {
        setSelectedClient(null);
      }
      onRefresh?.();
    } catch (e) {
      console.error("Failed to unenroll client:", e);
      alert(`Could not remove the system: ${e instanceof Error ? e.message : "unknown error"}`);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleOpenClientDetails = async (client: EnrolledClient) => {
    setSelectedClient(client);
    setIsLoadingDetails(true);
    try {
      const details = await fetchClientDetails(client.id);
      setClientEvents(details.events || []);
      setClientEventsTotal(details.eventsTotal ?? (details.events || []).length);
      setClientAlerts(details.alerts || []);
    } catch (e) {
      console.error("Failed to load client details", e);
      alert(`Could not load system details: ${e instanceof Error ? e.message : "unknown error"}`);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div className="min-w-0">
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2">
            <span>Enrolled Systems Fleet</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
              {clients.length} Total
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Real hardware and browser endpoints currently communicating with PhishGuard.
          </p>
        </div>
        <div className="flex items-center gap-3 min-w-0">
          <div className="relative min-w-0">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-neutral-400" />
            <input
              type="text"
              placeholder="Search by ID, OS, IP..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs pl-9 pr-3 py-2 rounded-lg focus:outline-none focus:border-[#ffffff] w-full sm:w-56"
            />
          </div>
          <button
            onClick={() => onNavigateTab("install_extension")}
            className="text-xs bg-white hover:bg-neutral-200 text-black font-semibold px-3.5 py-2 rounded-lg transition-colors shrink-0"
          >
            + Install Extension on New PC
          </button>
        </div>
      </div>

      {/* Systems Table */}
      <div className="bg-[#0e0e0e] border border-[#262626] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-neutral-300">
            <thead className="bg-[#161616] text-neutral-400 font-semibold border-b border-[#262626]">
              <tr>
                <th className="py-3 px-4">System / ID</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Platform & OS</th>
                <th className="py-3 px-4">Browser / Agent</th>
                <th className="py-3 px-4">First Seen</th>
                <th className="py-3 px-4">Last Seen</th>
                <th className="py-3 px-4">Telemetry Activity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {filteredClients.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-neutral-500">
                    <Laptop className="w-10 h-10 mx-auto mb-3 text-neutral-600 opacity-50" />
                    <div className="text-sm font-medium text-neutral-400">No Enrolled Systems Connected Yet</div>
                    <p className="text-xs text-neutral-500 max-w-md mx-auto mt-1">
                      Download the PhishGuard Chrome extension package, load it into your browser, and this workstation will automatically enroll within seconds.
                    </p>
                    <button
                      onClick={() => onNavigateTab("install_extension")}
                      className="mt-4 inline-flex items-center gap-1.5 text-xs bg-[#ffffff] hover:bg-[#e5e5e5] text-neutral-950 font-bold px-4 py-2 rounded-lg transition-all"
                    >
                      Download & Install Extension
                    </button>
                  </td>
                </tr>
              ) : (
                filteredClients.map(client => {
                  return (
                    <tr
                      key={client.id}
                      className="hover:bg-[#161616]/70 transition-colors cursor-pointer"
                      onClick={() => handleOpenClientDetails(client)}
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-neutral-100 flex items-center gap-2">
                          <Monitor className="w-4 h-4 text-[#ffffff]" />
                          <span>{client.clientName}</span>
                        </div>
                        <div className="text-[10px] font-mono text-neutral-500 mt-0.5">{client.id}</div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex flex-col gap-1">
                          {/* Persistent enrollment state — never changes on its own;
                              only an explicit delete removes this system. */}
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30 w-fit">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#ffffff]"></span>
                            ENROLLED
                          </span>
                          {/* Live connectivity — purely informational. OFFLINE means
                              no recent heartbeat, NOT removed: the system stays in
                              this list and in Total Enrolled Systems either way. */}
                          <span
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium w-fit ${
                              client.connectionStatus === "ONLINE"
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                                : "bg-neutral-700/30 text-neutral-400 border border-neutral-600/40"
                            }`}
                            title={client.connectionStatus === "ONLINE" ? "Heartbeat received recently" : "No recent heartbeat — still enrolled, not deleted"}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${client.connectionStatus === "ONLINE" ? "bg-emerald-400" : "bg-neutral-500"}`}></span>
                            {client.connectionStatus === "ONLINE" ? "Online" : "Offline"}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4 text-neutral-300">
                        <div>{client.os}</div>
                        <div className="text-[10px] text-neutral-500 font-mono">{client.ip}</div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="text-neutral-200">{client.browser}</div>
                        <div className="text-[10px] text-neutral-400">Ext v{client.extensionVersion}</div>
                      </td>

                      <td className="py-3 px-4 text-neutral-400 font-mono text-[11px] whitespace-nowrap">
                        {new Date(client.firstSeen).toLocaleDateString()}
                      </td>

                      <td className="py-3 px-4 text-neutral-300 font-mono text-[11px] whitespace-nowrap">
                        {new Date(client.lastSeen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2 font-mono text-[11px]">
                          <span className="text-[#ffffff]" title="URLs Evaluated">
                            {client.telemetryStats.totalScanned} URLs
                          </span>
                          {client.telemetryStats.phishingBlocked > 0 && (
                            <span className="text-rose-400 font-bold" title="Threats Blocked">
                              • {client.telemetryStats.phishingBlocked} blocked
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenClientDetails(client);
                            }}
                            className="text-xs text-[#ffffff] hover:underline font-medium"
                          >
                            Inspect →
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteClient(client.id, client.clientName);
                            }}
                            disabled={isDeleting}
                            className="p-1 text-neutral-500 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                            title="Unenroll & Remove System"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Client Detail Inspector Modal / Drawer */}
      {selectedClient && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-[#000000] border-l border-[#262626] h-full overflow-y-auto p-6 flex flex-col justify-between shadow-2xl">
            <div>
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-[#262626] pb-4 mb-6">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-bold text-neutral-100">{selectedClient.clientName}</h3>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
                      ENROLLED
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                        selectedClient.connectionStatus === "ONLINE"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : "bg-neutral-700/30 text-neutral-400 border border-neutral-600/40"
                      }`}
                      title={selectedClient.connectionStatus === "ONLINE" ? "Heartbeat received recently" : "No recent heartbeat — still enrolled, not deleted"}
                    >
                      {selectedClient.connectionStatus === "ONLINE" ? "Online" : "Offline"}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-neutral-500 mt-1">Client ID: {selectedClient.id}</div>
                </div>
                <button
                  onClick={() => setSelectedClient(null)}
                  className="p-1.5 rounded-lg bg-[#161616] hover:bg-[#232323] text-neutral-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Hardware & Version Specs */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl mb-6 text-xs">
                <div className="min-w-0">
                  <div className="text-neutral-500 text-[10px] uppercase">Operating System</div>
                  <div className="font-semibold text-neutral-200 mt-0.5 truncate">{selectedClient.os}</div>
                  <div className="text-[10px] text-neutral-500 font-mono mt-0.5 truncate">IP: {selectedClient.ip}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-neutral-500 text-[10px] uppercase">Browser & Version</div>
                  <div className="font-semibold text-neutral-200 mt-0.5 truncate">{selectedClient.browser}</div>
                  <div className="text-[10px] text-neutral-500 font-mono mt-0.5 truncate">Extension v{selectedClient.extensionVersion}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-neutral-500 text-[10px] uppercase">Activity Timestamps</div>
                  <div className="text-neutral-300 font-mono text-[11px] mt-0.5 truncate">First: {new Date(selectedClient.firstSeen).toLocaleDateString()}</div>
                  <div className="text-neutral-300 font-mono text-[11px] truncate">Last: {new Date(selectedClient.lastSeen).toLocaleTimeString()}</div>
                </div>
              </div>

              {/* Threat Alerts from this client */}
              <div className="mb-6">
                <h4 className="text-xs font-bold text-neutral-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                  <span>Threats Blocked on this Endpoint ({clientAlerts.length})</span>
                </h4>
                {clientAlerts.length === 0 ? (
                  <div className="p-3 bg-[#0e0e0e] border border-[#262626] rounded-lg text-neutral-500 text-xs text-center">
                    No active phishing threats blocked on this system.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {clientAlerts.map(alert => (
                      <div key={alert.id} className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-rose-400 font-mono">{alert.domain}</span>
                          <span className="font-mono text-[10px] text-neutral-400">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="text-[11px] text-neutral-300 mt-1">{alert.reasons.join(", ")}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* URL Activity History */}
              <div>
                <h4 className="text-xs font-bold text-neutral-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-[#ffffff]" />
                  <span>Telemetry Log ({clientEvents.length < clientEventsTotal ? `latest ${clientEvents.length} of ${clientEventsTotal}` : clientEventsTotal} events)</span>
                </h4>
                {isLoadingDetails ? (
                  <div className="p-6 text-center text-neutral-400 text-xs">Loading telemetry log...</div>
                ) : clientEvents.length === 0 ? (
                  <div className="p-3 bg-[#0e0e0e] border border-[#262626] rounded-lg text-neutral-500 text-xs text-center">
                    No URL navigations recorded for this client yet.
                  </div>
                ) : (
                  <div className="max-h-72 overflow-y-auto space-y-1.5 pr-1">
                    {clientEvents.map(e => (
                      <div key={e.id} className="p-2.5 bg-[#0e0e0e] border border-[#262626] rounded-lg text-xs flex items-center justify-between">
                        <div className="overflow-hidden mr-3">
                          <div className="font-mono text-neutral-200 truncate">{e.domain || e.url}</div>
                          <div className="text-[10px] text-neutral-500 truncate">{e.reason}</div>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            e.classification === "PHISHING"
                              ? "bg-rose-500/20 text-rose-400"
                              : e.classification === "SUSPICIOUS"
                              ? "bg-amber-500/20 text-amber-400"
                              : "bg-emerald-500/20 text-emerald-400"
                          }`}
                        >
                          {e.classification}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="pt-4 border-t border-[#262626] flex items-center gap-3">
              <button
                onClick={() => handleDeleteClient(selectedClient.id, selectedClient.clientName)}
                disabled={isDeleting}
                className="flex-1 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Unenroll & Remove System</span>
              </button>
              <button
                onClick={() => setSelectedClient(null)}
                className="flex-1 py-2 bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white rounded-lg text-xs font-medium"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
