import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../lib/api";
import { flags } from "../lib/flags";
import { useAuth } from "../state/auth";
import MachinePanel from "../components/MachinePanel";

const ALL_STAGES = ["dev", "staging", "prod", "personal"];

function StagePicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="checks">
      {ALL_STAGES.map((s) => (
        <label key={s}>
          <input
            type="checkbox"
            checked={value.includes(s)}
            onChange={(e) =>
              onChange(e.target.checked ? [...value, s] : value.filter((x) => x !== s))
            }
          />
          {s}
        </label>
      ))}
    </div>
  );
}

export default function ProjectSettingsPage() {
  const { project = "" } = useParams();
  const { session } = useAuth();
  const [detail, setDetail] = useState<api.ProjectDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteStages, setInviteStages] = useState<string[]>(["dev"]);
  const [grantTeamName, setGrantTeamName] = useState("");
  const [grantStages, setGrantStages] = useState<string[]>(["dev"]);
  const [inviteHours, setInviteHours] = useState(0); // 0 = standing grant
  const [busy, setBusy] = useState(false);

  const isOwner = detail?.owner === session?.email;

  const load = useCallback(async () => {
    try {
      setDetail(await api.projectDetail(project));
    } catch (err) {
      setError((err as Error).message);
    }
  }, [project]);

  useEffect(() => {
    void load();
  }, [load]);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function invite(e: FormEvent) {
    e.preventDefault();
    void run(async () => {
      await api.addProjectMember(project, inviteEmail.trim(), inviteStages, inviteHours || undefined);
      setInviteEmail("");
    });
  }

  function grant(e: FormEvent) {
    e.preventDefault();
    void run(async () => {
      await api.grantTeam(project, grantTeamName.trim(), grantStages);
      setGrantTeamName("");
    });
  }

  return (
    <div className="fade-in">
      <p className="kicker">
        <Link to={`/projects/${project}`} style={{ color: "inherit", textDecoration: "none" }}>
          ← {project}
        </Link>
      </p>
      <h1>Members &amp; teams</h1>
      {flags.ciem && isOwner && (
        <p>
          <Link to={`/projects/${project}/access`}>Access review: entitlements, findings, audit log →</Link>
        </p>
      )}
      <p className="sub">
        Inviting an email gives that address access to this project, and lets it log in
        even without an account of its own. Members see only the stages you grant.
      </p>

      {error && <p className="error">{error}</p>}
      {detail === null ? (
        <p className="loading">loading</p>
      ) : (
        <>
          <div className="panel">
            <div className="panel-head">
              <h2>Members</h2>
            </div>
            <ul className="list">
              {detail.members.map((m) => (
                <li key={m.email}>
                  <div className="grow mono" style={{ fontSize: 14 }}>
                    {m.email}
                  </div>
                  {m.stages.map((s) => (
                    <span key={s} className="tag">
                      {s}
                    </span>
                  ))}
                  {m.grantExpiresAt && (
                    <span className="tag" title={m.grantExpiresAt}>
                      until {m.grantExpiresAt.slice(0, 16).replace("T", " ")}
                    </span>
                  )}
                  <span className={`tag ${m.role === "owner" ? "accent" : ""}`}>{m.role}</span>
                  {isOwner && m.role !== "owner" && (
                    <button
                      className="btn quiet danger"
                      disabled={busy}
                      onClick={() => void run(() => api.removeProjectMember(project, m.email))}
                    >
                      remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
            {isOwner && (
              <div className="panel-body" style={{ borderTop: "1px solid var(--line)" }}>
                <form onSubmit={invite}>
                  <div className="row">
                    <label className="field">
                      <span>invite email</span>
                      <input
                        type="email"
                        value={inviteEmail}
                        onChange={(e) => setInviteEmail(e.target.value)}
                        placeholder="teammate@example.com"
                      />
                    </label>
                    <button className="btn" disabled={busy || !inviteEmail.trim() || inviteStages.length === 0}>
                      invite
                    </button>
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <StagePicker value={inviteStages} onChange={setInviteStages} />
                  </div>
                  {flags.ciem && (
                    <label className="field" style={{ marginTop: 14, maxWidth: 280 }}>
                      <span>access ends</span>
                      <select value={inviteHours} onChange={(e) => setInviteHours(Number(e.target.value))}>
                        <option value={0}>never (standing grant)</option>
                        <option value={4}>in 4 hours</option>
                        <option value={24}>in 24 hours</option>
                        <option value={168}>in 7 days</option>
                        <option value={720}>in 30 days</option>
                      </select>
                    </label>
                  )}
                </form>
              </div>
            )}
          </div>

          {flags.teams && (
          <div className="panel">
            <div className="panel-head">
              <h2>Team grants</h2>
            </div>
            {detail.teams.length === 0 ? (
              <p className="empty">No teams have access to this project.</p>
            ) : (
              <ul className="list">
                {detail.teams.map((t) => (
                  <li key={t.team}>
                    <div className="grow">
                      <Link className="plain" to={`/teams/${t.team}`}>
                        {t.team}
                      </Link>
                    </div>
                    {t.stages.map((s) => (
                      <span key={s} className="tag">
                        {s}
                      </span>
                    ))}
                    {isOwner && (
                      <button
                        className="btn quiet danger"
                        disabled={busy}
                        onClick={() => void run(() => api.revokeTeam(project, t.team))}
                      >
                        revoke
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {isOwner && (
              <div className="panel-body" style={{ borderTop: "1px solid var(--line)" }}>
                <form onSubmit={grant}>
                  <div className="row">
                    <label className="field">
                      <span>grant a team</span>
                      <input
                        type="text"
                        value={grantTeamName}
                        onChange={(e) => setGrantTeamName(e.target.value)}
                        placeholder="team name"
                        pattern="[\w.@+-]+"
                      />
                    </label>
                    <button className="btn" disabled={busy || !grantTeamName.trim() || grantStages.length === 0}>
                      grant
                    </button>
                  </div>
                  <div style={{ marginTop: 10 }}>
                    <StagePicker value={grantStages} onChange={setGrantStages} />
                  </div>
                </form>
              </div>
            )}
          </div>
          )}

          {flags.machineIdentities && (
            <MachinePanel
              project={project}
              machines={detail.machines ?? []}
              stages={ALL_STAGES}
              isOwner={isOwner}
              busy={busy}
              run={(fn) => void run(fn)}
              StagePicker={StagePicker}
            />
          )}
        </>
      )}
    </div>
  );
}
