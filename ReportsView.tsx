import React, { useEffect, useState } from "react";
import {
  Download,
  Filter,
  Printer,
  RefreshCw
} from "lucide-react";
import { jsPDF } from "jspdf";
import { EnrolledClient, ReportData } from "../types";
import { fetchReportData } from "../api";

interface ReportsViewProps {
  clients: EnrolledClient[];
}

const EMPTY_REPORT: ReportData = {
  scope: "ALL",
  generatedAt: new Date().toISOString(),
  systems: [],
  summary: { totalEvaluated: 0, safe: 0, suspicious: 0, phishing: 0, activeAlerts: 0 },
  topThreatDomains: [],
  events: [],
  alerts: [],
  perSystem: []
};

export const ReportsView: React.FC<ReportsViewProps> = ({ clients }) => {
  const [selectedSystem, setSelectedSystem] = useState("ALL");
  const [report, setReport] = useState<ReportData>(EMPTY_REPORT);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isGlobal = selectedSystem === "ALL";
  const client = clients.find(c => c.id === selectedSystem);
  const reportTitle = isGlobal
    ? "Enterprise Security Fleet Assessment Report"
    : `Endpoint Security Telemetry Report — ${client?.clientName || selectedSystem}`;

  const loadReport = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Every field below comes straight from the server-side database,
      // filtered by the selected scope on the server. A single-system
      // report can never contain another system's data because the
      // filtering happens in one place (GET /api/reports), not by slicing
      // shared client-side state.
      const data = await fetchReportData(selectedSystem);
      setReport(data);
    } catch (e) {
      console.error("Failed to load report data", e);
      setError("Failed to load report data from the server.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, [selectedSystem]);

  const { summary, topThreatDomains, events, alerts, perSystem } = report;

  const handlePrint = () => {
    window.print();
  };

  const handleExportPDF = () => {
    try {
      const doc = new jsPDF();
      const margin = 14;
      const pageWidth = 210;
      let y = 20;

      const ensureSpace = (needed: number) => {
        if (y + needed > 285) {
          doc.addPage();
          y = 20;
        }
      };

      doc.setFontSize(18);
      doc.setTextColor(15, 15, 15);
      doc.text("PhishGuard Enterprise SOC Report", margin, y);
      y += 8;

      doc.setFontSize(10);
      doc.setTextColor(90, 90, 90);
      doc.text(`Generated: ${new Date(report.generatedAt).toLocaleString()}`, margin, y);
      y += 6;
      doc.text(`Scope: ${isGlobal ? "All Enrolled Systems" : `${client?.clientName || selectedSystem} (${selectedSystem})`}`, margin, y);
      y += 10;

      doc.setDrawColor(20, 20, 20);
      doc.line(margin, y, pageWidth - margin, y);
      y += 8;

      doc.setFontSize(13);
      doc.setTextColor(15, 15, 15);
      doc.text("1. Security Telemetry Summary", margin, y);
      y += 7;
      doc.setFontSize(10);
      doc.setTextColor(40, 40, 40);
      doc.text(`Total URLs Evaluated: ${summary.totalEvaluated}`, margin + 4, y); y += 5.5;
      doc.text(`Phishing Intercepted (Blocked): ${summary.phishing}`, margin + 4, y); y += 5.5;
      doc.text(`Suspicious Sites Detected: ${summary.suspicious}`, margin + 4, y); y += 5.5;
      doc.text(`Clean / Safe Navigations: ${summary.safe}`, margin + 4, y); y += 5.5;
      doc.text(`Active Threat Alerts: ${summary.activeAlerts}`, margin + 4, y); y += 10;

      if (isGlobal && perSystem.length > 0) {
        ensureSpace(10 + perSystem.length * 6);
        doc.setFontSize(13);
        doc.setTextColor(15, 15, 15);
        doc.text("2. Per-System Breakdown", margin, y);
        y += 7;
        doc.setFontSize(9);
        perSystem.forEach(s => {
          ensureSpace(6);
          doc.setTextColor(40, 40, 40);
          doc.text(
            `${s.clientName} (${s.os}) — scanned ${s.totalScanned} | safe ${s.safe} | suspicious ${s.suspicious} | phishing ${s.phishing} | active alerts ${s.activeAlerts}`,
            margin + 4, y
          );
          y += 5.5;
        });
        y += 6;
      }

      ensureSpace(15);
      doc.setFontSize(13);
      doc.setTextColor(15, 15, 15);
      doc.text(`${isGlobal ? "3" : "2"}. Top Blocked Threat Domains`, margin, y);
      y += 7;
      doc.setFontSize(10);
      if (topThreatDomains.length === 0) {
        doc.setTextColor(110, 110, 110);
        doc.text("No malicious domains intercepted for this scope.", margin + 4, y);
        y += 8;
      } else {
        topThreatDomains.forEach((td, idx) => {
          ensureSpace(6);
          doc.setTextColor(40, 40, 40);
          doc.text(`${idx + 1}. ${td.domain} — ${td.count} interception(s)`, margin + 4, y);
          y += 5.5;
        });
        y += 6;
      }

      ensureSpace(15);
      doc.setFontSize(13);
      doc.setTextColor(15, 15, 15);
      doc.text(`${isGlobal ? "4" : "3"}. Security Events (Threat Alerts)`, margin, y);
      y += 7;
      doc.setFontSize(8.5);
      if (alerts.length === 0) {
        doc.setTextColor(110, 110, 110);
        doc.text("No threat alerts recorded for this scope.", margin + 4, y);
        y += 8;
      } else {
        alerts.slice(0, 60).forEach(a => {
          ensureSpace(5.5);
          doc.setTextColor(40, 40, 40);
          const line = `${new Date(a.timestamp).toLocaleString()} | ${a.clientName} | ${a.domain} | ${a.status}`;
          doc.text(line, margin + 4, y);
          y += 5;
        });
        y += 6;
      }

      ensureSpace(15);
      doc.setFontSize(13);
      doc.setTextColor(15, 15, 15);
      doc.text(`${isGlobal ? "5" : "4"}. URL History (most recent ${Math.min(events.length, 80)} of ${events.length})`, margin, y);
      y += 7;
      doc.setFontSize(8);
      if (events.length === 0) {
        doc.setTextColor(110, 110, 110);
        doc.text("No URL events recorded for this scope.", margin + 4, y);
      } else {
        events.slice(0, 80).forEach(e => {
          ensureSpace(5);
          doc.setTextColor(40, 40, 40);
          const line = `${new Date(e.timestamp).toLocaleString()} | ${e.clientName} | ${e.classification} | ${e.domain}`;
          doc.text(line, margin + 4, y);
          y += 4.6;
        });
      }

      const pageCount = (doc as any).internal.getNumberOfPages();
      for (let p = 1; p <= pageCount; p++) {
        doc.setPage(p);
        doc.setFontSize(8);
        doc.setTextColor(140, 140, 140);
        doc.text("Confidential — Generated by PhishGuard Enterprise Security Hub", margin, 292);
        doc.text(`Page ${p} of ${pageCount}`, pageWidth - margin - 20, 292);
      }

      doc.save(`phishguard-report-${isGlobal ? "all-systems" : selectedSystem}-${Date.now()}.pdf`);
    } catch (err) {
      console.error("PDF generation failed", err);
      alert("Failed to generate PDF report.");
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl print:hidden">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span>Executive Security Reports</span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Generate and export consolidated threat intelligence reports for compliance, SOC audits, and fleet posture.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadReport}
            disabled={isLoading}
            className="flex items-center gap-2 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white px-3 py-2 rounded-lg border border-[#2a2a2a] transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white px-3.5 py-2 rounded-lg border border-[#2a2a2a] transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>

          <button
            onClick={handleExportPDF}
            className="flex items-center gap-2 text-xs bg-white hover:bg-neutral-200 text-black font-bold px-4 py-2 rounded-lg transition-colors shadow"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </button>
        </div>
      </div>

      {/* Scope Filter Controls */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl flex items-center gap-4 print:hidden">
        <div className="flex items-center gap-2 text-xs text-neutral-400">
          <Filter className="w-3.5 h-3.5" />
          <span>Report Scope:</span>
        </div>
        <select
          value={selectedSystem}
          onChange={e => setSelectedSystem(e.target.value)}
          className="bg-[#161616] border border-[#2a2a2a] text-neutral-200 text-xs px-3 py-2 rounded-lg focus:outline-none"
        >
          <option value="ALL">All Enrolled Systems (Enterprise Fleet)</option>
          {clients.map(c => (
            <option key={c.id} value={c.id}>
              {c.clientName} ({c.os} — {c.id.slice(-6)})
            </option>
          ))}
        </select>
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>

      {/* Printable Report Document */}
      <div id="phishguard-report-printable" className="bg-white text-black border border-[#262626] print:border-none p-8 rounded-xl shadow-xl space-y-6">
        <div className="border-b border-neutral-300 pb-6 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <PhishGuardFlagMark className="w-8 h-8" />
              <h1 className="text-xl font-bold text-black">{reportTitle}</h1>
            </div>
            <p className="text-xs text-neutral-600 mt-2">
              Generated: {new Date(report.generatedAt).toUTCString()} | PhishGuard Security Operations
            </p>
          </div>
          <div className="text-right text-xs font-mono text-neutral-600">
            <div>STATUS: VERIFIED</div>
            <div className="text-black font-bold mt-0.5">DATABASE AUTHENTIC</div>
          </div>
        </div>

        <div>
          <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">1. Executive Telemetry Overview</h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <StatBox label="URLs Evaluated" value={summary.totalEvaluated} />
            <StatBox label="Safe Navigations" value={summary.safe} />
            <StatBox label="Suspicious" value={summary.suspicious} />
            <StatBox label="Phishing Intercepted" value={summary.phishing} />
            <StatBox label="Active Alerts" value={summary.activeAlerts} />
          </div>
        </div>

        {isGlobal && perSystem.length > 0 && (
          <div>
            <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">2. Per-System Breakdown</h3>
            <div className="border border-neutral-300 rounded-lg overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-neutral-100 text-neutral-600 font-semibold">
                  <tr>
                    <th className="py-2 px-3">System</th>
                    <th className="py-2 px-3">OS</th>
                    <th className="py-2 px-3">Scanned</th>
                    <th className="py-2 px-3">Safe</th>
                    <th className="py-2 px-3">Suspicious</th>
                    <th className="py-2 px-3">Phishing</th>
                    <th className="py-2 px-3">Active Alerts</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-200">
                  {perSystem.map(s => (
                    <tr key={s.clientId}>
                      <td className="py-2 px-3 font-semibold">{s.clientName}</td>
                      <td className="py-2 px-3">{s.os}</td>
                      <td className="py-2 px-3 font-mono">{s.totalScanned}</td>
                      <td className="py-2 px-3 font-mono">{s.safe}</td>
                      <td className="py-2 px-3 font-mono">{s.suspicious}</td>
                      <td className="py-2 px-3 font-mono">{s.phishing}</td>
                      <td className="py-2 px-3 font-mono">{s.activeAlerts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div>
          <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">
            {isGlobal ? "3" : "2"}. Top Blocked Threat Domains
          </h3>
          <div className="bg-neutral-50 border border-neutral-300 rounded-lg p-4">
            {topThreatDomains.length === 0 ? (
              <div className="text-xs text-neutral-500 py-4 text-center">No confirmed phishing domains logged for this scope.</div>
            ) : (
              <div className="space-y-2">
                {topThreatDomains.map((td, idx) => (
                  <div key={td.domain} className="flex items-center justify-between text-xs py-1 border-b border-neutral-200 last:border-none">
                    <div className="flex items-center gap-2">
                      <span className="text-neutral-400 font-mono">{idx + 1}.</span>
                      <span className="font-mono text-black font-bold">{td.domain}</span>
                    </div>
                    <span className="text-black font-mono font-semibold">{td.count} interception(s)</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div>
          <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">
            {isGlobal ? "4" : "3"}. Security Events (Threat Alerts) — {alerts.length} total
          </h3>
          <div className="border border-neutral-300 rounded-lg overflow-hidden max-h-72 overflow-y-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-neutral-100 text-neutral-600 font-semibold sticky top-0">
                <tr>
                  <th className="py-2 px-3">Timestamp</th>
                  <th className="py-2 px-3">System</th>
                  <th className="py-2 px-3">Domain</th>
                  <th className="py-2 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200">
                {alerts.length === 0 ? (
                  <tr><td colSpan={4} className="py-4 text-center text-neutral-400">No threat alerts for this scope.</td></tr>
                ) : alerts.slice(0, 100).map(a => (
                  <tr key={a.id}>
                    <td className="py-1.5 px-3 whitespace-nowrap font-mono">{new Date(a.timestamp).toLocaleString()}</td>
                    <td className="py-1.5 px-3">{a.clientName}</td>
                    <td className="py-1.5 px-3 font-mono">{a.domain}</td>
                    <td className="py-1.5 px-3 font-semibold">{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-wider mb-3">
            {isGlobal ? "5" : "4"}. URL History — {events.length} total (showing latest {Math.min(events.length, 150)})
          </h3>
          <div className="border border-neutral-300 rounded-lg overflow-hidden max-h-96 overflow-y-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-neutral-100 text-neutral-600 font-semibold sticky top-0">
                <tr>
                  <th className="py-2 px-3">Timestamp</th>
                  <th className="py-2 px-3">System</th>
                  <th className="py-2 px-3">Classification</th>
                  <th className="py-2 px-3">Domain</th>
                  <th className="py-2 px-3">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200">
                {events.length === 0 ? (
                  <tr><td colSpan={5} className="py-4 text-center text-neutral-400">No URL events for this scope.</td></tr>
                ) : events.slice(0, 150).map(e => (
                  <tr key={e.id}>
                    <td className="py-1.5 px-3 whitespace-nowrap font-mono">{new Date(e.timestamp).toLocaleString()}</td>
                    <td className="py-1.5 px-3">{e.clientName}</td>
                    <td className="py-1.5 px-3 font-semibold">{e.classification}</td>
                    <td className="py-1.5 px-3 font-mono">
                      {e.domain}
                      {e.ruleTriggered && (
                        <span className="ml-1.5 text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-black text-white">
                          {e.ruleType === "WHITELIST" ? "Whitelist Rule" : "Blacklist Rule"}
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 px-3 font-mono">{(e.score * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="border-t border-neutral-300 pt-4 text-[10px] text-neutral-500 flex items-center justify-between">
          <span>PhishGuard Enterprise SOC Engine</span>
          <span>Client–Server Endpoint Telemetry Protocol</span>
        </div>
      </div>
    </div>
  );
};

const StatBox: React.FC<{ label: string; value: number }> = ({ label, value }) => (
  <div className="p-4 bg-neutral-50 border border-neutral-300 rounded-lg">
    <div className="text-[11px] text-neutral-500">{label}</div>
    <div className="text-2xl font-bold text-black font-mono mt-1">{value}</div>
  </div>
);

const PhishGuardFlagMark: React.FC<{ className?: string }> = ({ className }) => (
  <svg viewBox="0 0 32 32" className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="13" y="2" width="2.4" height="28" rx="1" fill="#000" />
    <rect x="15.4" y="4" width="13.5" height="10.5" fill="#000" />
  </svg>
);
