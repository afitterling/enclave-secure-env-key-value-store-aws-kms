import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../lib/api";

/**
 * CIEM view for one project (enterprise `ciem` feature, owner only): who can
 * reach which stage and by which path, how much of it is actually used, what
 * looks excessive, and the audit trail behind those numbers. Fixes go through
 * the ordinary member/binding endpoints, so they are exactly as reversible as
 * an edit on the settings page.
 */

const day = (iso?: string) => (iso ? iso.slice(0, 10) : "never");
const machineId = (principal: string) => principal.split("/").slice(1).join("/");
const hoursLeft = (iso?: string) =>
  iso ? Math.max(1, Math.ceil((Date.parse(iso) - Date.now()) / 3_600_000)) : undefined;

function Severity({ s }: { s: api.Finding["severity"] }) {
  const color = s === "high" ? "var(--danger)" : s === "medium" ? "var(--accent)" : "var(--ink-dim)";
  return (
    <span className="tag" style={{ borderColor: color, color }}>
      {s}
    </span>
  );
}

export default function AccessReviewPage() {
  const { project = "" } = useParams();
  const [report, setReport] = useState<api.EntitlementReport | null>(null);
  const [detail, setDetail] = useState<api.ProjectDetail | null>(null);
  const [events, setEvents] = useState<api.AuditEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [r, d, a] = await Promise.all([api.entitlements(project), api.projectDetail(project), api.auditLog(project)]);
      setReport(r);
      setDetail(d);
      setEvents(a.events);
      setCursor(a.cursor);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [project]);

  useEffect(() => {
    void load();
  }, [load]);

  async function more() {
    if (!cursor) return;
    const a = await api.auditLog(project, cursor);
    setEvents((e) => [...e, ...a.events]);
    setCursor(a.cursor);
  }

  async function apply(fix: api.Fix) {
    if (!detail) return;
    setBusy(true);
    setError(null);
    try {
      if (fix.via === "binding") {
        const binding = detail.machines?.find((m) => m.id === machineId(fix.principal));
        if (!binding) throw new Error("binding not found; reload the page");
        const { createdBy: _b, createdAt: _a, grantExpiresAt, ...rest } = binding;
        const left = hoursLeft(grantExpiresAt);
        if (fix.kind === "removePrincipal") await api.removeMachine(project, binding.id);
        else if (fix.kind === "downgrade") await api.upsertMachine(project, { ...rest, access: "read" }, left);
        else if (fix.kind === "removeStage") {
          const stages = binding.stages.filter((s) => s !== fix.stage);
          if (stages.length) await api.upsertMachine(project, { ...rest, stages }, left);
          else await api.removeMachine(project, binding.id);
        }
      } else {
        const member = detail.members.find((m) => m.email === fix.principal);
        if (!member) throw new Error("member not found; reload the page");
        const left = hoursLeft(member.grantExpiresAt);
        if (fix.kind === "removePrincipal") await api.removeProjectMember(project, member.email);
        else if (fix.kind === "timebox") await api.addProjectMember(project, member.email, member.stages, 24 * 7);
        else if (fix.kind === "removeStage") {
          const stages = member.stages.filter((s) => s !== fix.stage);
          if (stages.length) await api.addProjectMember(project, member.email, stages, left);
          else await api.removeProjectMember(project, member.email);
        }
      }
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const fixLabel = (f: api.Fix) =>
    f.kind === "removeStage"
      ? `remove ${f.stage}`
      : f.kind === "removePrincipal"
        ? "revoke"
        : f.kind === "downgrade"
          ? "make read-only"
          : "expire in 7 days";

  return (
    <div className="fade-in">
      <p className="kicker">
        <Link to={`/projects/${project}`} style={{ color: "inherit", textDecoration: "none" }}>
          ← {project}
        </Link>
      </p>
      <h1>Access review</h1>
      <p className="sub">
        Every path by which a person or workload reaches this project's stages, compared with what
        they actually used. Findings name a fix; applying it edits the membership or binding.
      </p>
      {error && <p className="error">{error}</p>}
      {!report ? (
        <p className="loading">loading</p>
      ) : (
        <>
          <div className="panel">
            <div className="panel-head">
              <h2>Permission utilization</h2>
            </div>
            <div className="panel-body">
              <p style={{ margin: 0 }}>
                <span className="mono" style={{ fontSize: 28 }}>
                  {Math.round(report.utilization.ratio * 100)}%
                </span>{" "}
                <span style={{ color: "var(--ink-dim)" }}>
                  of {report.utilization.granted} granted stage permissions were used in the last{" "}
                  {report.windowDays} days ({report.utilization.used} used). Owners are not counted.
                </span>
              </p>
            </div>
          </div>

          <div className="panel" style={{ marginTop: 28 }}>
            <div className="panel-head">
              <h2>Findings ({report.findings.length})</h2>
            </div>
            {report.findings.length === 0 ? (
              <div className="panel-body" style={{ color: "var(--ink-dim)" }}>
                Nothing excessive found.
              </div>
            ) : (
              <ul className="list">
                {report.findings.map((f) => (
                  <li key={f.id} style={{ flexWrap: "wrap" }}>
                    <Severity s={f.severity} />
                    <div className="grow" style={{ minWidth: 0 }}>
                      <div>
                        {f.title} <span className="mono" style={{ fontSize: 13 }}>· {f.principal}</span>
                        {f.via.startsWith("team:") && <span className="tag">{f.via}</span>}
                      </div>
                      <div style={{ fontSize: 13, color: "var(--ink-dim)" }}>{f.detail}</div>
                    </div>
                    {f.fix && (
                      <button className="btn quiet" disabled={busy} onClick={() => void apply(f.fix!)}>
                        {fixLabel(f.fix)}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="panel" style={{ marginTop: 28 }}>
            <div className="panel-head">
              <h2>Entitlements</h2>
            </div>
            <ul className="list">
              {report.entitlements.map((e) => (
                <li key={`${e.principal}|${e.via}`} style={{ flexWrap: "wrap" }}>
                  <div className="grow" style={{ minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 14, overflowWrap: "anywhere" }}>
                      {e.principal}
                    </div>
                    <div style={{ fontSize: 12.5, color: "var(--ink-dim)" }}>
                      via {e.via} · last used {day(e.lastUsed)}
                      {e.grantExpiresAt && ` · ${e.expired ? "expired" : "expires"} ${day(e.grantExpiresAt)}`}
                    </div>
                  </div>
                  {e.stages.map((s) => (
                    <span
                      key={s}
                      className="tag"
                      title={
                        e.usage[s]
                          ? `${e.usage[s].reads} reads, ${e.usage[s].writes} writes`
                          : "no recorded use"
                      }
                      style={e.usage[s] ? undefined : { opacity: 0.5, textDecoration: "line-through" }}
                    >
                      {s}
                    </span>
                  ))}
                  <span className={`tag ${e.access === "write" ? "accent" : ""}`}>{e.kind === "machine" ? e.access : e.via === "owner" ? "owner" : "member"}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="panel" style={{ marginTop: 28 }}>
            <div className="panel-head">
              <h2>Audit log</h2>
            </div>
            <ul className="list">
              {events.length === 0 && (
                <li style={{ color: "var(--ink-dim)" }}>No events recorded yet.</li>
              )}
              {events.map((ev, i) => (
                <li key={`${ev.at}-${i}`} style={{ flexWrap: "wrap", fontSize: 13 }}>
                  <span className="mono" style={{ color: "var(--ink-dim)" }}>
                    {ev.at.replace("T", " ").slice(0, 19)}
                  </span>
                  <span className="tag">{ev.action}</span>
                  <span className="tag">{ev.stage}</span>
                  <div className="grow mono" style={{ minWidth: 0, overflowWrap: "anywhere" }}>
                    {ev.principal}
                    {ev.actor && ` (for ${ev.actor})`}
                    {ev.file && ` · ${ev.file}`}
                  </div>
                  {ev.ip && <span style={{ color: "var(--ink-faint)" }}>{ev.ip}</span>}
                </li>
              ))}
            </ul>
            {cursor && (
              <div className="panel-body" style={{ borderTop: "1px solid var(--line)" }}>
                <button className="btn quiet" onClick={() => void more()}>
                  older events
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
