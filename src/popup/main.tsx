import { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Cookie,
  ExternalLink,
  FileCode,
  Globe,
  LockKeyhole,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Waypoints,
  X,
} from "lucide-react";
import "../styles/global.css";
import type { SecurityFinding, TabSnapshot } from "../shared/types";
import { generateReport } from "../reports/report-generator";

const send = <T,>(message: unknown) => chrome.runtime.sendMessage(message) as Promise<T>;

const statusColor = (classification: string) =>
  classification === "safe"
    ? "text-safe"
    : classification === "caution"
      ? "text-caution"
      : classification === "dangerous"
        ? "text-danger"
        : "text-mist-400";

const statusBg = (classification: string) =>
  classification === "safe"
    ? "bg-safe/15 text-safe border-safe/30"
    : classification === "caution"
      ? "bg-caution/15 text-caution border-caution/30"
      : classification === "dangerous"
        ? "bg-danger/15 text-danger border-danger/30"
        : "bg-ink-800 text-mist-400 border-ink-600";

const severityBadge = (severity: string) => {
  switch (severity) {
    case "critical":
      return "bg-danger/20 text-danger border-danger/40";
    case "high":
      return "bg-danger/15 text-red-300 border-red-500/30";
    case "medium":
      return "bg-caution/15 text-caution border-caution/30";
    case "low":
      return "bg-amber-500/10 text-amber-300 border-amber-500/20";
    default:
      return "bg-ink-800 text-mist-400 border-ink-700";
  }
};

type TabType = "overview" | "domain" | "headers" | "findings";

function App() {
  const [snapshot, setSnapshot] = useState<TabSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const load = async (force = false) => {
    setLoading(true);
    setError(null);
    try {
      const response = await send<{ ok: boolean; snapshot: TabSnapshot | null; error: string | null }>({
        type: force ? "RESCAN" : "GET_SNAPSHOT",
        force,
      });
      if (!response.ok || !response.snapshot) {
        setError(response.error ?? "No assessment is available for this tab.");
      } else {
        setSnapshot(response.snapshot);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sentinel is unavailable.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // The popup can open while the tab's background assessment is still changing.
    // Force a fresh snapshot on open instead of presenting a cached evidence result.
    void load(true);
  }, []);

  const assessment = snapshot?.assessment;
  const factors = useMemo(() => assessment?.topFactors.slice(0, 4) ?? [], [assessment]);
  const findings = useMemo(() => assessment?.findings ?? [], [assessment]);
  const headers = snapshot?.headers;
  const domainIntel = snapshot?.domainIntel;

  const confidencePct =
    assessment && typeof assessment.confidenceScore === "number" ? Math.round(assessment.confidenceScore * 100) : null;

  return (
    <main className="w-[430px] min-h-[580px] bg-ink-950 p-4 text-mist-100 flex flex-col font-sans select-none">
      {/* Extension Header */}
      <header className="mb-3 flex items-center justify-between pb-2 border-b border-ink-800">
        <div className="flex items-center gap-2.5">
          <div className="grid h-8 w-8 place-items-center rounded-xl bg-sentinel/15 text-sentinel shadow-glow">
            <Shield size={18} />
          </div>
          <div>
            <div className="font-bold tracking-wider text-sm text-mist-100 flex items-center gap-2">
              SENTINEL
              {assessment && confidencePct !== null && (
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-ink-800 text-mist-300 border border-ink-700">
                  {confidencePct}% confidence
                </span>
              )}
            </div>
            <div className="text-[11px] text-mist-400">Website trust & phishing guard</div>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            className="button-ghost p-1.5"
            onClick={() => void load(true)}
            title="Rescan page"
            aria-label="Refresh assessment"
          >
            <RefreshCw size={15} className={loading ? "animate-spin text-sentinel" : ""} />
          </button>
          <button
            className="button-ghost p-1.5"
            aria-label="Open settings"
            onClick={() => void send({ type: "OPEN_OPTIONS" })}
            title="Settings"
          >
            <Settings size={16} />
          </button>
        </div>
      </header>

      {/* Loading View */}
      {loading && (
        <div className="panel flex flex-col items-center justify-center gap-3 p-10 text-mist-300 flex-1 my-auto">
          <RefreshCw className="animate-spin text-sentinel" size={24} />
          <div className="text-sm font-medium">Auditing observable evidence...</div>
          <div className="text-xs text-mist-500">Checking domain, certificates, headers, and DOM</div>
        </div>
      )}

      {/* Error View */}
      {!loading && error && (
        <div className="panel p-6 flex-1 my-auto">
          <div className="mb-3 flex items-center gap-2 text-caution font-semibold">
            <ShieldAlert size={20} /> Assessment unavailable
          </div>
          <p className="text-sm text-mist-400 leading-relaxed">{error}</p>
          <div className="mt-4 pt-3 border-t border-ink-800 flex justify-end">
            <button className="button-secondary text-xs" onClick={() => void load(true)}>
              Rescan page
            </button>
          </div>
        </div>
      )}

      {/* Main Tabbed Content */}
      {!loading && snapshot && assessment && (
        <div className="flex-1 flex flex-col">
          {/* Navigation Tabs */}
          <nav className="flex gap-1 mb-3 bg-ink-900/80 p-1 rounded-xl border border-ink-800">
            <button
              onClick={() => setActiveTab("overview")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "overview"
                  ? "bg-ink-750 text-sentinel border border-sentinel/30 shadow-sm"
                  : "text-mist-400 hover:text-mist-200"
              }`}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab("domain")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "domain"
                  ? "bg-ink-750 text-sentinel border border-sentinel/30 shadow-sm"
                  : "text-mist-400 hover:text-mist-200"
              }`}
            >
              Domain & SSL
            </button>
            <button
              onClick={() => setActiveTab("headers")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                activeTab === "headers"
                  ? "bg-ink-750 text-sentinel border border-sentinel/30 shadow-sm"
                  : "text-mist-400 hover:text-mist-200"
              }`}
            >
              Headers
            </button>
            <button
              onClick={() => setActiveTab("findings")}
              className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1 ${
                activeTab === "findings"
                  ? "bg-ink-750 text-sentinel border border-sentinel/30 shadow-sm"
                  : "text-mist-400 hover:text-mist-200"
              }`}
            >
              Findings
              {findings.length > 0 && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-ink-800 text-mist-300">
                  {findings.length}
                </span>
              )}
            </button>
          </nav>

          {/* TAB 1: OVERVIEW */}
          {activeTab === "overview" && (
            <div className="space-y-3 animate-fade-up">
              {/* Hero Trust Score Panel */}
              <section className="panel p-4 overflow-hidden relative">
                <div className="flex items-start justify-between">
                  <div className="max-w-[240px]">
                    <div className="label">Current website</div>
                    <div className="mt-0.5 truncate font-bold text-base text-mist-100" title={snapshot.domain}>
                      {snapshot.domain || "Unknown page"}
                    </div>
                    <div className="mt-1 text-xs text-mist-400 flex items-center gap-1.5">
                      <LockKeyhole size={13} className={snapshot.connection.secure ? "text-safe" : "text-danger"} />
                      <span>{snapshot.connection.explanation}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className={`text-4xl font-black tracking-tight ${statusColor(assessment.classification)}`}>
                      {assessment.score === null ? "—" : assessment.score}
                    </div>
                    <span
                      className={`inline-block mt-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${statusBg(
                        assessment.classification,
                      )}`}
                    >
                      {assessment.classification}
                    </span>
                  </div>
                </div>

                {assessment.score !== null && (
                  <div className="h-1.5 mt-3.5 overflow-hidden rounded-full bg-ink-800">
                    <div
                      className={`h-full transition-all duration-500 ${
                        assessment.classification === "safe"
                          ? "bg-safe"
                          : assessment.classification === "dangerous"
                            ? "bg-danger"
                            : "bg-caution"
                      }`}
                      style={{ width: `${assessment.score}%` }}
                    />
                  </div>
                )}
                {assessment.score === null && (
                  <p className="mt-3 text-[11px] text-mist-400">Insufficient observable evidence for a numeric score.</p>
                )}
              </section>

              {/* High-Risk Alert Banner */}
              {assessment.critical && (
                <div className="rounded-xl border border-danger/60 bg-danger/10 p-3.5 animate-pulse">
                  <div className="flex items-center gap-2 font-bold text-danger text-sm">
                    <ShieldAlert size={17} /> High-confidence security risk
                  </div>
                  <p className="mt-1 text-xs text-mist-200 leading-relaxed">
                    Deceptive credential collection or verified malicious match detected. Do not submit credentials, OTPs,
                    or payment details.
                  </p>
                </div>
              )}

              {/* Quick Health Indicators Grid */}
              <section className="panel p-3">
                <div className="label mb-2 px-1">Security overview</div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg bg-ink-850/60 p-2.5 border border-ink-800">
                    <div className="flex items-center gap-1.5 text-mist-400 mb-1">
                      <Globe size={13} /> Domain age
                    </div>
                    <div className="font-semibold text-mist-200">
                      {domainIntel?.domainAgeDays !== null && domainIntel?.domainAgeDays !== undefined
                        ? `${domainIntel.domainAgeDays} days old`
                        : "Lookup pending"}
                    </div>
                  </div>

                  <div className="rounded-lg bg-ink-850/60 p-2.5 border border-ink-800">
                    <div className="flex items-center gap-1.5 text-mist-400 mb-1">
                      <FileCode size={13} /> Security headers
                    </div>
                    <div className="font-semibold text-mist-200">
                      {headers?.available ? `${headers.presentCount}/6 present` : "Pending audit"}
                    </div>
                  </div>

                  <div className="rounded-lg bg-ink-850/60 p-2.5 border border-ink-800">
                    <div className="flex items-center gap-1.5 text-mist-400 mb-1">
                      <Waypoints size={13} /> Trackers
                    </div>
                    <div className="font-semibold text-mist-200">
                      {snapshot.trackers.recognizedCount} recognized · {snapshot.trackers.unknownCount} third-party
                    </div>
                  </div>

                  <div className="rounded-lg bg-ink-850/60 p-2.5 border border-ink-800">
                    <div className="flex items-center gap-1.5 text-mist-400 mb-1">
                      <Cookie size={13} /> Cookies
                    </div>
                    <div className="font-semibold text-mist-200">
                      {snapshot.cookies.available
                        ? `${snapshot.cookies.total} total · ${snapshot.cookies.concernCount} concerns`
                        : "Unavailable"}
                    </div>
                  </div>
                </div>
              </section>

              {/* Key Score Factors */}
              <section className="panel p-3.5">
                <div className="label mb-2">Key Assessment Factors</div>
                {factors.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-mist-300">
                    {factors.map((factor) => (
                      <li className="flex items-start gap-1.5" key={factor}>
                        <ChevronRight className="mt-0.5 shrink-0 text-sentinel" size={13} />
                        <span>{factor}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-mist-400">No material risk factors observed in observable evidence.</p>
                )}
              </section>
            </div>
          )}

          {/* TAB 2: DOMAIN & SSL */}
          {activeTab === "domain" && (
            <div className="space-y-3 animate-fade-up">
              {/* Domain Registration Details */}
              <section className="panel p-3.5">
                <div className="label mb-2.5 flex items-center gap-1.5">
                  <Globe size={13} /> Domain Registration (RDAP)
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-ink-800/80">
                    <span className="text-mist-400">Registrable Domain:</span>
                    <span className="font-mono font-medium text-mist-200">{domainIntel?.domain || snapshot.domain}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-ink-800/80">
                    <span className="text-mist-400">Domain Age:</span>
                    <span className="font-medium text-mist-200">
                      {domainIntel?.domainAgeDays !== null && domainIntel?.domainAgeDays !== undefined
                        ? `${domainIntel.domainAgeDays} days`
                        : "Unavailable / Private"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-ink-800/80">
                    <span className="text-mist-400">Registration Date:</span>
                    <span className="font-medium text-mist-200">
                      {domainIntel?.registrationDate
                        ? new Date(domainIntel.registrationDate).toLocaleDateString()
                        : "Not disclosed"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <span className="text-mist-400">Registrar:</span>
                    <span className="font-medium text-mist-200 truncate max-w-[200px]">
                      {domainIntel?.registrar || "Protected / Unknown"}
                    </span>
                  </div>
                </div>
              </section>

              {/* Certificate Transparency Intelligence */}
              <section className="panel p-3.5">
                <div className="label mb-2.5 flex items-center gap-1.5">
                  <LockKeyhole size={13} /> Certificate Transparency (crt.sh)
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-ink-800/80">
                    <span className="text-mist-400">Current Protocol:</span>
                    <span
                      className={`font-semibold ${snapshot.connection.secure ? "text-safe" : "text-danger"}`}
                    >
                      {snapshot.connection.protocol.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-ink-800/80">
                    <span className="text-mist-400">Certificate Age:</span>
                    <span className="font-medium text-mist-200">
                      {domainIntel?.ctCertAgeDays !== null && domainIntel?.ctCertAgeDays !== undefined
                        ? `${domainIntel.ctCertAgeDays} days ago`
                        : "Observed via browser"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <span className="text-mist-400">CT Log Entries:</span>
                    <span className="font-medium text-mist-200">
                      {domainIntel?.ctCertTotal !== null && domainIntel?.ctCertTotal !== undefined
                        ? `${domainIntel.ctCertTotal} logged`
                        : "Local handshake only"}
                    </span>
                  </div>
                </div>
              </section>

              {/* DNS & Email Authentication Records */}
              <section className="panel p-3.5">
                <div className="label mb-2.5 flex items-center gap-1.5">
                  <Waypoints size={13} /> DNS Security & Email Auth (DoH)
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2 rounded-lg bg-ink-850 border border-ink-800">
                    <div className="text-mist-400 text-[10px] uppercase">SPF Record</div>
                    <div className="mt-1 flex items-center gap-1 font-semibold">
                      {domainIntel?.hasSpf ? (
                        <span className="text-safe flex items-center gap-1">
                          <Check size={13} /> Configured
                        </span>
                      ) : (
                        <span className="text-mist-400 flex items-center gap-1">
                          <X size={13} /> Not found
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="p-2 rounded-lg bg-ink-850 border border-ink-800">
                    <div className="text-mist-400 text-[10px] uppercase">DMARC Policy</div>
                    <div className="mt-1 flex items-center gap-1 font-semibold truncate">
                      {domainIntel?.hasDmarc ? (
                        <span className="text-safe flex items-center gap-1 truncate" title={domainIntel.dmarcPolicy ?? "present"}>
                          <Check size={13} /> {domainIntel.dmarcPolicy ?? "Active"}
                        </span>
                      ) : (
                        <span className="text-mist-400 flex items-center gap-1">
                          <X size={13} /> Not found
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* TAB 3: SECURITY HEADERS */}
          {activeTab === "headers" && (
            <div className="space-y-3 animate-fade-up">
              <section className="panel p-3.5">
                <div className="flex items-center justify-between mb-2">
                  <div className="label">HTTP Security Posture</div>
                  <span className="text-xs font-semibold text-sentinel">
                    {headers?.available ? `${headers.presentCount} / 6 Headers Active` : "Audit in progress"}
                  </span>
                </div>
                <p className="text-xs text-mist-400 mb-3">
                  Security headers defend visitors against cross-site scripting (XSS), clickjacking, and protocol
                  downgrade attacks.
                </p>

                {headers?.headers && headers.headers.length > 0 ? (
                  <div className="space-y-2">
                    {headers.headers.map((h) => (
                      <div
                        key={h.name}
                        className="p-2.5 rounded-lg bg-ink-850/80 border border-ink-800 hover:border-ink-700 transition"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-mist-100 flex items-center gap-1.5">
                            {h.label}
                            <span className="text-[10px] font-mono font-normal text-mist-500">({h.name})</span>
                          </span>
                          {h.present ? (
                            <span className="text-[11px] font-semibold text-safe flex items-center gap-1 bg-safe/10 px-2 py-0.5 rounded-full">
                              <Check size={12} /> Present
                            </span>
                          ) : (
                            <span className="text-[11px] font-semibold text-mist-400 flex items-center gap-1 bg-ink-800 px-2 py-0.5 rounded-full">
                              <X size={12} /> Missing
                            </span>
                          )}
                        </div>
                        <p className="mt-1 text-[11px] text-mist-400 leading-tight">{h.explanation}</p>
                        {h.present && h.value && (
                          <div className="mt-1.5 font-mono text-[10px] text-mist-400 bg-ink-900/90 p-1.5 rounded border border-ink-800/80 truncate">
                            {h.value}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-6 text-center text-xs text-mist-400">
                    No headers captured for this origin.
                  </div>
                )}
              </section>
            </div>
          )}

          {/* TAB 4: FINDINGS & EVIDENCE */}
          {activeTab === "findings" && (
            <div className="space-y-2.5 animate-fade-up">
              {findings.length === 0 ? (
                <div className="panel p-8 text-center text-mist-400 text-xs">
                  <CheckCircle2 size={32} className="mx-auto mb-2 text-safe" />
                  No security warnings or vulnerabilities identified.
                </div>
              ) : (
                findings.map((f: SecurityFinding) => {
                  const isExpanded = expandedFindingId === f.id;
                  return (
                    <div
                      key={f.id}
                      className="panel p-3 transition border border-ink-750 hover:border-ink-600 cursor-pointer"
                      onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span
                              className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${severityBadge(
                                f.severity,
                              )}`}
                            >
                              {f.severity}
                            </span>
                            <span className="text-[10px] font-medium text-mist-400 uppercase tracking-wider">
                              {f.category}
                            </span>
                            {f.penalty > 0 && (
                              <span className="text-[10px] font-semibold text-danger">-{f.penalty} pts</span>
                            )}
                          </div>
                          <div className="mt-1 text-xs font-semibold text-mist-100">{f.title}</div>
                        </div>

                        <button className="button-ghost p-1 text-mist-400">
                          {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                        </button>
                      </div>

                      <p className="mt-1 text-xs text-mist-300 leading-relaxed">{f.explanation}</p>

                      {isExpanded && (
                        <div className="mt-2.5 pt-2.5 border-t border-ink-800 space-y-2 text-xs">
                          {f.evidence && f.evidence.length > 0 && (
                            <div>
                              <div className="text-[10px] uppercase font-bold text-mist-400 tracking-wider mb-1">
                                Observable Evidence
                              </div>
                              <ul className="space-y-1 bg-ink-900/90 p-2 rounded-lg border border-ink-800">
                                {f.evidence.map((item, idx) => (
                                  <li key={idx} className="font-mono text-[10px] text-mist-300 break-all">
                                    • {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {f.remediation && (
                            <div className="p-2 rounded-lg bg-sentinel/10 border border-sentinel/20 text-mist-200">
                              <span className="font-bold text-sentinel text-[11px] block mb-0.5">Recommended Action</span>
                              <span className="text-[11px]">{f.remediation}</span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* Bottom Action Footer */}
          <footer className="mt-auto pt-3 border-t border-ink-800 flex gap-2">
            <button
              className="button-primary flex-1 text-xs py-2"
              onClick={() => void send({ type: "OPEN_OPTIONS" })}
            >
              <SlidersHorizontal size={14} /> Protection Settings
            </button>
            <button
              className="button-secondary text-xs py-2 px-3"
              title="Download detailed forensic assessment JSON"
              onClick={() => {
                const report = generateReport(snapshot);
                const blob = new Blob([JSON.stringify({ format: "sentinel-report", report }, null, 2)], {
                  type: "application/json",
                });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = `sentinel-${snapshot.domain || "report"}.json`;
                link.click();
                URL.revokeObjectURL(url);
              }}
            >
              <ExternalLink size={14} /> Export
            </button>
          </footer>
        </div>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
