import React, { useCallback, useEffect, useRef, useState } from "react";
import { AlertOctagon, AlertTriangle, CheckCircle2, Pencil, Plus, Power, ShieldCheck, Trash2, Zap } from "lucide-react";
import { PhishingRule, WhitelistRule } from "../types";
import {
  addPhishingRule,
  addWhitelistRule,
  deletePhishingRule,
  deleteWhitelistRule,
  errMsg,
  fetchRules,
  updatePhishingRule,
  updateWhitelistRule
} from "../api";

type EditState = { type: "WHITELIST" | "PHISHING"; id: string; pattern: string; text: string; severity: "HIGH" | "CRITICAL" };

export const SecurityRulesView: React.FC = () => {
  const [whitelist, setWhitelist] = useState<WhitelistRule[]>([]);
  const [phishingRules, setPhishingRules] = useState<PhishingRule[]>([]);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [editing, setEditing] = useState<EditState | null>(null);

  // New Whitelist Rule State
  const [whitePattern, setWhitePattern] = useState("");
  const [whiteDesc, setWhiteDesc] = useState("");
  const [isAddingWhite, setIsAddingWhite] = useState(false);

  // New Phishing Rule State
  const [phishPattern, setPhishPattern] = useState("");
  const [phishSeverity, setPhishSeverity] = useState<"HIGH" | "CRITICAL">("HIGH");
  const [phishReason, setPhishReason] = useState("");
  const [isAddingPhish, setIsAddingPhish] = useState(false);

  // Newest request wins; a failed reload keeps the rules already on screen
  // (it never replaces them with an empty list).
  const seq = useRef(0);
  const loadRules = useCallback(async () => {
    const id = ++seq.current;
    try {
      const data = await fetchRules();
      if (id !== seq.current) return;
      setWhitelist(data.whitelist);
      setPhishingRules(data.phishing);
      setHasLoaded(true);
      setLoadError(null);
    } catch (e) {
      if (id !== seq.current) return;
      console.error("Failed to load rules", e);
      setLoadError(errMsg(e, "Failed to load rules from the server."));
    }
  }, []);

  useEffect(() => { loadRules(); }, [loadRules]);

  const run = async (busy: string | null, fn: () => Promise<void>) => {
    setActionError(null);
    if (busy) setBusyId(busy);
    try { await fn(); await loadRules(); }
    catch (e) { setActionError(errMsg(e)); }
    finally { if (busy) setBusyId(null); }
  };

  const handleAddWhitelist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whitePattern.trim()) return;
    setIsAddingWhite(true);
    await run(null, async () => {
      await addWhitelistRule(whitePattern.trim(), whiteDesc.trim());
      setWhitePattern(""); setWhiteDesc("");
    });
    setIsAddingWhite(false);
  };

  const handleAddPhishing = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!phishPattern.trim()) return;
    setIsAddingPhish(true);
    await run(null, async () => {
      await addPhishingRule(phishPattern.trim(), phishSeverity, phishReason.trim());
      setPhishPattern(""); setPhishReason("");
    });
    setIsAddingPhish(false);
  };

  const handleDeleteWhitelist = async (id: string) => {
    if (!confirm("Are you sure you want to remove this whitelist rule?")) return;
    await run(id, () => deleteWhitelistRule(id));
  };
  const handleDeletePhishing = async (id: string) => {
    if (!confirm("Are you sure you want to remove this phishing rule?")) return;
    await run(id, () => deletePhishingRule(id));
  };

  const toggleWhitelist = (r: WhitelistRule) => run(r.id, async () => { await updateWhitelistRule(r.id, { enabled: !r.enabled }); });
  const togglePhishing = (r: PhishingRule) => run(r.id, async () => { await updatePhishingRule(r.id, { enabled: !r.enabled }); });

  const saveEdit = async () => {
    if (!editing) return;
    const ed = editing;
    await run(ed.id, async () => {
      if (ed.type === "WHITELIST") await updateWhitelistRule(ed.id, { pattern: ed.pattern, description: ed.text });
      else await updatePhishingRule(ed.id, { pattern: ed.pattern, reason: ed.text, severity: ed.severity });
      setEditing(null);
    });
  };

  const activeCount = whitelist.filter(r => r.enabled).length + phishingRules.filter(r => r.enabled).length;

  const EditForm = () => editing && (
    <div className="p-2.5 bg-[#161616] border border-white/30 rounded-lg text-xs space-y-2">
      <input value={editing.pattern} onChange={e => setEditing({ ...editing, pattern: e.target.value })}
        className="w-full bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-white font-mono" />
      <div className="flex gap-2">
        <input value={editing.text} onChange={e => setEditing({ ...editing, text: e.target.value })}
          placeholder={editing.type === "WHITELIST" ? "Description" : "Threat reason"}
          className="flex-1 bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-white" />
        {editing.type === "PHISHING" && (
          <select value={editing.severity} onChange={e => setEditing({ ...editing, severity: e.target.value as any })}
            className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-2 py-2 rounded focus:outline-none">
            <option value="HIGH">High Risk</option>
            <option value="CRITICAL">Critical</option>
          </select>
        )}
      </div>
      <div className="flex justify-end gap-2">
        <button onClick={() => setEditing(null)} className="px-3 py-1 rounded border border-[#2a2a2a] text-neutral-300 hover:bg-[#232323]">Cancel</button>
        <button onClick={saveEdit} disabled={busyId === editing.id} className="px-3 py-1 rounded bg-white text-black font-semibold hover:bg-neutral-200">Save</button>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2">
            <span>Security Rules & Policy</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
              {hasLoaded ? `${activeCount} Active Rules` : "Loading…"}
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Global network detection policies enforced directly across all connected browser extensions during evaluation and heartbeat sync.
          </p>
        </div>

        {/* Sync status indicator */}
        <div className="flex items-center gap-2 bg-[#161616] border border-[#2a2a2a] px-3.5 py-2 rounded-lg text-xs">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-neutral-300">Extension Sync: <strong className="text-emerald-400">≤ 30s</strong></span>
        </div>
      </div>

      {(loadError || actionError) && (
        <div className="flex items-center gap-2 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs px-4 py-2.5 rounded-lg">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span className="flex-1">{actionError || loadError}{!actionError && hasLoaded ? " — showing the last rules received." : ""}</span>
          {loadError && !actionError && <button onClick={loadRules} className="underline hover:text-rose-300 shrink-0">Retry</button>}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Area A: Whitelist Rules */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-neutral-100">Whitelist Rules (Always Allowed)</h3>
              </div>
              <span className="text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-bold">
                {whitelist.length} Rules
              </span>
            </div>
            <p className="text-xs text-neutral-400 mb-4">
              Domains or URL patterns in this list bypass phishing heuristics and are guaranteed safe across all client endpoints.
            </p>

            {/* Add Rule Form */}
            <form onSubmit={handleAddWhitelist} className="bg-[#161616] border border-[#262626] p-3 rounded-lg mb-4 space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <input
                  type="text"
                  placeholder="e.g. internal.corp.com or mydomain.org"
                  value={whitePattern}
                  onChange={e => setWhitePattern(e.target.value)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-emerald-400 font-mono"
                  required
                />
                <input
                  type="text"
                  placeholder="Description / Reason"
                  value={whiteDesc}
                  onChange={e => setWhiteDesc(e.target.value)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-emerald-400"
                />
              </div>
              <button
                type="submit"
                disabled={isAddingWhite}
                className="w-full flex items-center justify-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold py-1.5 rounded transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Whitelist Rule</span>
              </button>
            </form>

            {/* Whitelist Table */}
            <div className="max-h-72 overflow-y-auto space-y-1.5">
              {!hasLoaded ? (
                <div className="py-6 text-center text-neutral-500 text-xs">{loadError ? "Rules could not be loaded." : "Loading rules from the database…"}</div>
              ) : whitelist.length === 0 ? (
                <div className="py-6 text-center text-neutral-500 text-xs">
                  No whitelist rules configured. Add internal corporate domains to exempt them from scans.
                </div>
              ) : (
                whitelist.map(rule => editing?.id === rule.id ? <React.Fragment key={rule.id}>{EditForm()}</React.Fragment> : (
                  <div
                    key={rule.id}
                    className={`flex items-center justify-between p-2.5 bg-[#161616] border border-[#262626] rounded-lg text-xs ${rule.enabled ? "" : "opacity-50"}`}
                  >
                    <div className="overflow-hidden mr-2">
                      <div className="font-mono font-bold text-neutral-100 truncate">{rule.pattern}{!rule.enabled && <span className="ml-2 text-[9px] font-sans uppercase text-neutral-400">disabled</span>}</div>
                      <div className="text-[10px] text-neutral-400 truncate">{rule.description}</div>
                    </div>
                    <div className="flex items-center shrink-0">
                      <button onClick={() => toggleWhitelist(rule)} disabled={busyId === rule.id} className={`p-1 transition-colors ${rule.enabled ? "text-emerald-400 hover:text-emerald-300" : "text-neutral-500 hover:text-white"}`} title={rule.enabled ? "Disable rule" : "Enable rule"}><Power className="w-3.5 h-3.5" /></button>
                      <button onClick={() => setEditing({ type: "WHITELIST", id: rule.id, pattern: rule.pattern, text: rule.description, severity: "HIGH" })} className="text-neutral-500 hover:text-white p-1 transition-colors" title="Edit Rule"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => handleDeleteWhitelist(rule.id)} disabled={busyId === rule.id} className="text-neutral-500 hover:text-rose-400 p-1 transition-colors" title="Delete Rule"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Area B: Phishing Rules */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-5 h-5 text-rose-500" />
                <h3 className="text-sm font-bold text-neutral-100">Phishing Rules (Mandatory Block)</h3>
              </div>
              <span className="text-xs font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded font-bold">
                {phishingRules.length} Rules
              </span>
            </div>
            <p className="text-xs text-neutral-400 mb-4">
              Domains or patterns matching these rules are immediately intercepted, blocked with a warning screen, and alerted.
            </p>

            {/* Add Phishing Form */}
            <form onSubmit={handleAddPhishing} className="bg-[#161616] border border-[#262626] p-3 rounded-lg mb-4 space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <input
                  type="text"
                  placeholder="e.g. evil-login-phish.xyz"
                  value={phishPattern}
                  onChange={e => setPhishPattern(e.target.value)}
                  className="sm:col-span-2 bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-rose-400 font-mono"
                  required
                />
                <select
                  value={phishSeverity}
                  onChange={e => setPhishSeverity(e.target.value as any)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-2 py-2 rounded focus:outline-none"
                >
                  <option value="HIGH">High Risk</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <input
                type="text"
                placeholder="Threat Reason (e.g. Credential Harvester Campaign)"
                value={phishReason}
                onChange={e => setPhishReason(e.target.value)}
                className="w-full bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-rose-400"
              />
              <button
                type="submit"
                disabled={isAddingPhish}
                className="w-full flex items-center justify-center gap-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold py-1.5 rounded transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Phishing Rule</span>
              </button>
            </form>

            {/* Phishing Rules Table */}
            <div className="max-h-72 overflow-y-auto space-y-1.5">
              {!hasLoaded ? (
                <div className="py-6 text-center text-neutral-500 text-xs">{loadError ? "Rules could not be loaded." : "Loading rules from the database…"}</div>
              ) : phishingRules.length === 0 ? (
                <div className="py-6 text-center text-neutral-500 text-xs">
                  No custom phishing rules configured. You can define specific domains or malicious patterns to block immediately.
                </div>
              ) : (
                phishingRules.map(rule => editing?.id === rule.id ? <React.Fragment key={rule.id}>{EditForm()}</React.Fragment> : (
                  <div
                    key={rule.id}
                    className={`flex items-center justify-between p-2.5 bg-[#161616] border border-rose-500/20 rounded-lg text-xs ${rule.enabled ? "" : "opacity-50"}`}
                  >
                    <div className="overflow-hidden mr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-rose-400 truncate">{rule.pattern}</span>
                        <span className="text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300">
                          {rule.severity}
                        </span>
                        {!rule.enabled && <span className="text-[9px] uppercase text-neutral-400">disabled</span>}
                      </div>
                      <div className="text-[10px] text-neutral-400 truncate">{rule.reason}</div>
                    </div>
                    <div className="flex items-center shrink-0">
                      <button onClick={() => togglePhishing(rule)} disabled={busyId === rule.id} className={`p-1 transition-colors ${rule.enabled ? "text-emerald-400 hover:text-emerald-300" : "text-neutral-500 hover:text-white"}`} title={rule.enabled ? "Disable rule" : "Enable rule"}><Power className="w-3.5 h-3.5" /></button>
                      <button onClick={() => setEditing({ type: "PHISHING", id: rule.id, pattern: rule.pattern, text: rule.reason, severity: rule.severity })} className="text-neutral-500 hover:text-white p-1 transition-colors" title="Edit Rule"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => handleDeletePhishing(rule.id)} disabled={busyId === rule.id} className="text-neutral-500 hover:text-rose-400 p-1 transition-colors" title="Delete Rule"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
