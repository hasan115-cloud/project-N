import React, { useCallback, useEffect, useRef, useState } from "react";
import { Filter, Globe, Laptop, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { EnrolledClient, UrlEvent } from "../types";
import { errMsg, fetchEvents, isAbort } from "../api";

interface UrlHistoryViewProps {
  clients: EnrolledClient[];
  // System scope is owned by App and shared with the Overview, so the two
  // views can never describe different record sets.
  selectedClient: string;
  onSelectClient: (clientId: string) => void;
}

const PAGE_SIZE = 200;
const POLL_MS = 10_000;

// Newest first; ties broken by id so ordering is fully deterministic.
const byNewest = (x: UrlEvent, y: UrlEvent) =>
  y.timestamp.localeCompare(x.timestamp) || y.id.localeCompare(x.id);

export const UrlHistoryView: React.FC<UrlHistoryViewProps> = ({ clients, selectedClient, onSelectClient }) => {
  const [events, setEvents] = useState<UrlEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // `search` is what the user is typing; `appliedSearch` is what the list is
  // actually filtered by. Every fetch (initial, poll, load-more) reads the SAME
  // committed filters from `filtersRef`, so the poll can never query with a
  // stale search term (the old code captured `search` in a closure created
  // before the user typed, so each poll silently reverted their results).
  const [search, setSearch] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [selectedClassification, setSelectedClassification] = useState("ALL");

  const filtersRef = useRef({ clientId: selectedClient, classification: selectedClassification, search: appliedSearch });
  filtersRef.current = { clientId: selectedClient, classification: selectedClassification, search: appliedSearch };
  const filterKey = `${selectedClient}|${selectedClassification}|${appliedSearch}`;

  // Only the newest request may write; superseded requests are aborted.
  const generation = useRef(0);
  const inflight = useRef<AbortController | null>(null);

  /** replace=true: new filter → start over. Otherwise: merge newest page into what is loaded. */
  const loadFirstPage = useCallback(async (mode: "replace" | "merge") => {
    const gen = generation.current;
    inflight.current?.abort();
    const ctrl = new AbortController();
    inflight.current = ctrl;
    if (mode === "replace") { setIsLoading(true); setLoadError(null); }
    try {
      const page = await fetchEvents({ ...filtersRef.current, limit: PAGE_SIZE, offset: 0 }, ctrl.signal);
      if (gen !== generation.current) return; // filters changed while in flight
      setEvents(prev => {
        if (mode === "replace") return page.events;
        // MERGE: fresh rows win, everything already loaded is kept → a poll can
        // never make loaded history shrink or vanish.
        const map = new Map(prev.map(e => [e.id, e]));
        page.events.forEach(e => map.set(e.id, e));
        return Array.from(map.values()).sort(byNewest);
      });
      setTotal(page.total);
      setHasLoaded(true);
      setLoadError(null);
    } catch (e) {
      if (isAbort(e) || gen !== generation.current) return;
      console.error("Failed to load events", e);
      // Keep whatever is already on screen; just say the refresh failed.
      setLoadError(errMsg(e, "Failed to load URL history from the server."));
    } finally {
      if (gen === generation.current) setIsLoading(false);
    }
  }, []);

  const loadMore = async () => {
    const gen = generation.current;
    setIsLoadingMore(true);
    try {
      const page = await fetchEvents({ ...filtersRef.current, limit: PAGE_SIZE, offset: events.length });
      if (gen !== generation.current) return;
      setEvents(prev => {
        const map = new Map(prev.map(e => [e.id, e]));
        page.events.forEach(e => map.set(e.id, e));
        return Array.from(map.values()).sort(byNewest);
      });
      setTotal(page.total);
    } catch (e) {
      setLoadError(errMsg(e, "Failed to load more records."));
    } finally {
      setIsLoadingMore(false);
    }
  };

  // Filter change → reset the list and load fresh. Then poll (merge) while visible.
  useEffect(() => {
    generation.current++;
    setEvents([]);
    setTotal(0);
    setHasLoaded(false);
    loadFirstPage("replace");
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") loadFirstPage("merge");
    }, POLL_MS);
    return () => { clearInterval(timer); inflight.current?.abort(); };
  }, [filterKey, loadFirstPage]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setAppliedSearch(search.trim());
  };

  const handleRefreshClick = () => {
    generation.current++;
    loadFirstPage("replace");
  };

  const ruleTriggeredLabel = (evt: UrlEvent): string | null => {
    if (!evt.ruleTriggered) return null;
    return "Rule Triggered";
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div className="min-w-0">
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2 flex-wrap">
            <span>URL Telemetry History</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
              {total} Records
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Navigation and manual-scan history across all connected PhishGuard endpoints, stored in the database.
          </p>
        </div>

        <button
          onClick={handleRefreshClick}
          disabled={isLoading}
          className="flex items-center gap-2 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white px-3.5 py-2 rounded-lg border border-[#2a2a2a] transition-colors self-start sm:self-auto shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-[#ffffff]" : ""}`} />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl flex flex-wrap gap-3 items-center justify-between">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-neutral-400" />
          <input
            type="text"
            placeholder="Search by domain, URL, or trigger reason..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#161616] border border-[#262626] text-neutral-200 text-xs pl-9 pr-3 py-2 rounded-lg focus:outline-none focus:border-[#ffffff]"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          {/* Client Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Laptop className="w-3.5 h-3.5" />
            <select
              value={selectedClient}
              onChange={e => onSelectClient(e.target.value)}
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

          {/* Classification Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={selectedClassification}
              onChange={e => setSelectedClassification(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs px-2.5 py-2 rounded-lg focus:outline-none"
            >
              <option value="ALL">All Classifications</option>
              <option value="SAFE">Safe</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="PHISHING">Phishing</option>
            </select>
          </div>
        </div>
      </div>

      {loadError && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs px-4 py-2.5 rounded-lg flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
          <span>{loadError}</span>
        </div>
      )}

      {/* URL History Table */}
      <div className="bg-[#0e0e0e] border border-[#262626] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-neutral-300">
            <thead className="bg-[#161616] text-neutral-400 font-semibold border-b border-[#262626]">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">System / Endpoint</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Domain & Destination</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Heuristics & Reason</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {!hasLoaded && !loadError ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-neutral-400">
                    <RefreshCw className="w-6 h-6 mx-auto animate-spin text-[#ffffff] mb-2" />
                    Loading complete URL history from database...
                  </td>
                </tr>
              ) : !hasLoaded ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-neutral-500 text-xs">
                    Could not load URL history. Use “Refresh Records” to retry.
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-neutral-500">
                    <Globe className="w-10 h-10 mx-auto mb-2 opacity-50 text-neutral-600" />
                    <div className="text-sm font-medium text-neutral-400">No URL Events Matched</div>
                    <p className="text-xs text-neutral-500 max-w-sm mx-auto mt-1">
                      {appliedSearch || selectedClient !== "ALL" || selectedClassification !== "ALL"
                        ? "Try clearing your filters to view more records."
                        : "No browsing events received yet. Once the extension is active on a system, evaluated URLs will appear here."}
                    </p>
                  </td>
                </tr>
              ) : (
                events.map(evt => {
                  const ruleLabel = ruleTriggeredLabel(evt);
                  return (
                    <tr key={evt.id} className="hover:bg-[#161616]/60 transition-colors">
                      <td className="py-3 px-4 text-neutral-400 font-mono text-[11px] whitespace-nowrap">
                        <div>{new Date(evt.timestamp).toLocaleDateString()}</div>
                        <div className="text-[10px] text-neutral-500">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="font-semibold text-neutral-200">{evt.clientName}</div>
                        <div className="text-[10px] text-neutral-500 font-mono">{evt.source}</div>
                      </td>

                      <td className="py-3 px-4">
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

                      <td className="py-3 px-4 max-w-xs">
                        <div className="font-mono text-neutral-200 truncate font-semibold">{evt.domain}</div>
                        <div className="text-[10px] text-neutral-500 truncate" title={evt.url}>{evt.url}</div>
                        {ruleLabel && (
                          <div className="mt-1.5 rounded border border-white/25 bg-white/5 px-2 py-1.5 text-[10px] leading-relaxed">
                            <div className="inline-flex items-center gap-1 font-bold uppercase tracking-wide text-white">
                              <ShieldAlert className="w-2.5 h-2.5" />
                              {ruleLabel}
                            </div>
                            <div className="text-neutral-300">
                              Matched Rule: <span className="font-mono text-white">{evt.matchedPattern || "(rule since deleted)"}</span>
                            </div>
                            <div className="text-neutral-300">
                              Rule Type: <span className="text-white">{evt.ruleType === "WHITELIST" ? "Whitelist" : "Phishing / Blacklist"}</span>
                              {" · "}Action: <span className={evt.verdict === "BLOCKED" ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>{evt.verdict === "BLOCKED" ? "Blocked" : "Allowed"}</span>
                            </div>
                          </div>
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono">
                        <span className={`text-xs font-bold ${evt.score >= 0.65 ? "text-rose-400" : evt.score >= 0.4 ? "text-amber-400" : "text-emerald-400"}`}>
                          {(evt.score * 100).toFixed(0)}%
                        </span>
                      </td>

                      <td className="py-3 px-4 text-neutral-300 text-[11px] max-w-sm truncate" title={evt.reason}>
                        {evt.reason || "Standard heuristic"}
                      </td>

                      <td className="py-3 px-4 font-semibold text-[11px]">
                        <span className={evt.verdict === "BLOCKED" ? "text-rose-400" : evt.verdict === "WARNING" ? "text-amber-400" : "text-emerald-400"}>
                          {evt.verdict}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between gap-3 px-4 py-3 border-t border-[#262626] text-xs text-neutral-400">
          <span>
            Showing {events.length} of {total} matching records, newest first, loaded from the database.
          </span>
          {events.length < total && (
            <button
              onClick={loadMore}
              disabled={isLoadingMore}
              className="shrink-0 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-200 px-3.5 py-1.5 rounded-lg border border-[#2a2a2a] transition-colors"
            >
              {isLoadingMore ? "Loading…" : `Load ${Math.min(PAGE_SIZE, total - events.length)} more`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
