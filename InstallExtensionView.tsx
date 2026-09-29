import React, { useEffect, useState } from "react";
import {
  Check,
  CheckCircle2,
  Copy,
  Download,
  FolderOpen,
  Laptop,
  Radio,
  Server,
  Terminal,
  ToggleRight,
  Wifi
} from "lucide-react";
import { fetchHealth, fetchServerInfo, getDownloadExtensionUrl } from "../api";

export const InstallExtensionView: React.FC = () => {
  const [serverInfo, setServerInfo] = useState<{ serverUrl: string; version: string; status: string }>({
    serverUrl: window.location.origin,
    version: "",
    status: "checking"
  });
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [testStatus, setTestStatus] = useState<"IDLE" | "TESTING" | "SUCCESS" | "FAILED">("IDLE");

  useEffect(() => {
    fetchServerInfo().then(setServerInfo).catch(() => {});
  }, []);

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(serverInfo.serverUrl);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  const handleTestConnection = async () => {
    setTestStatus("TESTING");
    try {
      // Succeeds only if the API answers AND the database + schema are healthy.
      const h = await fetchHealth();
      setTestStatus(h.status === "ok" && h.database === "up" ? "SUCCESS" : "FAILED");
    } catch {
      setTestStatus("FAILED");
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2">
            <span>Install & Deploy PhishGuard Agent</span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Deploy the PhishGuard Chrome extension to any local machine or networked workstation.
          </p>
        </div>

        <a
          href={getDownloadExtensionUrl()}
          download="phishguard-extension.zip"
          className="flex items-center justify-center gap-2 bg-[#179c54] hover:bg-[#158849] text-white text-xs font-bold px-5 py-2.5 rounded-lg shadow transition-all self-start sm:self-auto"
        >
          <Download className="w-4 h-4" />
          <span>Download Extension (.ZIP)</span>
        </a>
      </div>

      {/* Connection & Configuration Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="md:col-span-2 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
          <div className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-1 flex items-center gap-2">
            <Server className="w-4 h-4 text-[#ffffff]" />
            <span>Target Central Server Endpoint</span>
          </div>
          <p className="text-xs text-neutral-400 mb-3">
            The downloaded ZIP package is automatically pre-configured with this central server endpoint:
          </p>

          <div className="flex items-center gap-2 bg-[#161616] border border-[#262626] p-2.5 rounded-lg">
            <code className="text-xs font-mono text-emerald-400 font-bold flex-1 truncate">
              {serverInfo.serverUrl}
            </code>
            <button
              onClick={handleCopyUrl}
              className="px-2.5 py-1 text-xs bg-[#1a2a45] hover:bg-[#23385c] text-neutral-200 rounded flex items-center gap-1 transition-colors"
            >
              {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedUrl ? "Copied" : "Copy"}</span>
            </button>
          </div>
        </div>

        {/* Server Connectivity Status Card */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-1 flex items-center gap-2">
              <Wifi className="w-4 h-4 text-emerald-400" />
              <span>Server Readiness</span>
            </div>
            <p className="text-xs text-neutral-400">
              Verifies the API is reachable and connected to the Supabase database. Extensions authenticate with their own per-system credentials.
            </p>
          </div>

          <div className="pt-4 flex items-center justify-between">
            <span className="text-xs font-mono text-neutral-300">
              {testStatus === "TESTING" ? "Checking..." : testStatus === "SUCCESS" ? "Connected" : "Operational"}
            </span>
            <button
              onClick={handleTestConnection}
              disabled={testStatus === "TESTING"}
              className="text-xs bg-[#161616] hover:bg-[#232323] text-[#ffffff] border border-[#ffffff]/30 px-3 py-1.5 rounded-lg font-medium transition-colors"
            >
              Test Connectivity
            </button>
          </div>
        </div>
      </div>

      {/* Step-by-Step Installation Walkthrough */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-6 rounded-xl">
        <h3 className="text-base font-bold text-neutral-100 mb-2">Step-by-Step Chrome Installation Guide</h3>
        <p className="text-xs text-neutral-400 mb-6">
          Follow these 5 simple steps on any computer running Google Chrome, Brave, Edge, or Chromium to enroll the device:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {/* Step 1 */}
          <div className="bg-[#161616] border border-[#262626] p-4 rounded-xl relative">
            <div className="w-7 h-7 rounded-full bg-[#1c2e4d] text-[#ffffff] font-mono font-bold text-xs flex items-center justify-center mb-3">
              1
            </div>
            <div className="font-semibold text-xs text-neutral-200 mb-1 flex items-center gap-1.5">
              <Download className="w-3.5 h-3.5 text-[#ffffff]" />
              <span>Download ZIP</span>
            </div>
            <p className="text-[11px] text-neutral-400">
              Click the download button to get the pre-configured <code className="text-neutral-300">phishguard-extension.zip</code> file.
            </p>
          </div>

          {/* Step 2 */}
          <div className="bg-[#161616] border border-[#262626] p-4 rounded-xl relative">
            <div className="w-7 h-7 rounded-full bg-[#1c2e4d] text-[#ffffff] font-mono font-bold text-xs flex items-center justify-center mb-3">
              2
            </div>
            <div className="font-semibold text-xs text-neutral-200 mb-1 flex items-center gap-1.5">
              <FolderOpen className="w-3.5 h-3.5 text-[#ffffff]" />
              <span>Extract Folder</span>
            </div>
            <p className="text-[11px] text-neutral-400">
              Extract the ZIP to a permanent folder on your computer (e.g. <code className="text-neutral-300">Downloads/phishguard-extension</code>).
            </p>
          </div>

          {/* Step 3 */}
          <div className="bg-[#161616] border border-[#262626] p-4 rounded-xl relative">
            <div className="w-7 h-7 rounded-full bg-[#1c2e4d] text-[#ffffff] font-mono font-bold text-xs flex items-center justify-center mb-3">
              3
            </div>
            <div className="font-semibold text-xs text-neutral-200 mb-1 flex items-center gap-1.5">
              <ToggleRight className="w-3.5 h-3.5 text-[#ffffff]" />
              <span>Developer Mode</span>
            </div>
            <p className="text-[11px] text-neutral-400">
              Open Chrome, type <code className="text-neutral-300">chrome://extensions</code> in the address bar, and switch on <strong>Developer mode</strong> (top right).
            </p>
          </div>

          {/* Step 4 */}
          <div className="bg-[#161616] border border-[#262626] p-4 rounded-xl relative">
            <div className="w-7 h-7 rounded-full bg-[#1c2e4d] text-[#ffffff] font-mono font-bold text-xs flex items-center justify-center mb-3">
              4
            </div>
            <div className="font-semibold text-xs text-neutral-200 mb-1 flex items-center gap-1.5">
              <FolderOpen className="w-3.5 h-3.5 text-[#ffffff]" />
              <span>Load Unpacked</span>
            </div>
            <p className="text-[11px] text-neutral-400">
              Click the <strong>Load unpacked</strong> button and choose the extracted extension folder containing <code className="text-neutral-300">manifest.json</code>.
            </p>
          </div>

          {/* Step 5 */}
          <div className="bg-[#161616] border border-[#262626] p-4 rounded-xl relative">
            <div className="w-7 h-7 rounded-full bg-emerald-500/20 text-emerald-400 font-mono font-bold text-xs flex items-center justify-center mb-3">
              5
            </div>
            <div className="font-semibold text-xs text-emerald-400 mb-1 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Automatic Fleet Sync</span>
            </div>
            <p className="text-[11px] text-neutral-400">
              The extension instantly establishes communication, registers its hardware profile, and starts protecting navigation!
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
