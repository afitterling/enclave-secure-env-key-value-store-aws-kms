import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import * as api from "../lib/api";

/**
 * Machine identities: bind a CI job or workload's own identity to stages of
 * this project, so it can pull env files without a human login or a stored key.
 * The server re-validates everything (lib/machines.ts); the presets here only
 * shape the claims so owners do not have to write them by hand.
 */

const GITHUB = "https://token.actions.githubusercontent.com";
type Preset = "github" | "oidc" | "aws";

function describe(m: api.MachineBinding): ReactNode {
  if (m.kind === "aws") return `AWS role ${m.role} in ${m.account}`;
  const claims = Object.entries(m.claims ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(" · ");
  return `${m.issuer === GITHUB ? "GitHub Actions" : m.issuer} · ${claims}`;
}

function usage(project: string, m: api.MachineBinding, audience: string): string {
  if (m.kind === "aws") {
    return `enclave machine-login --project ${project} --identity ${m.id} --aws\nenclave exec -p ${project} -s ${m.stages[0]} -- ./start.sh`;
  }
  if (m.issuer === GITHUB) {
    return [
      "permissions:",
      "  id-token: write   # lets the job request an OIDC token",
      "steps:",
      "  - run: pip install enclave-envoy",
      `  - run: enclave machine-login --project ${project} --identity ${m.id} --github`,
      `  - run: enclave exec -p ${project} -s ${m.stages[0]} -- npm run deploy`,
    ].join("\n");
  }
  return `# request the token for audience: ${m.audience ?? audience}\nenclave machine-login --project ${project} --identity ${m.id} --oidc-token-file /var/run/secrets/tokens/enclave`;
}

export default function MachinePanel({
  project,
  machines,
  stages,
  isOwner,
  busy,
  run,
  StagePicker,
}: {
  project: string;
  machines: api.MachineBinding[];
  stages: string[];
  isOwner: boolean;
  busy: boolean;
  run: (fn: () => Promise<unknown>) => void;
  StagePicker: (p: { value: string[]; onChange: (v: string[]) => void }) => JSX.Element;
}) {
  const [audience, setAudience] = useState("");
  const [preset, setPreset] = useState<Preset>("github");
  const [id, setId] = useState("");
  const [repo, setRepo] = useState("");
  const [ref, setRef] = useState("refs/heads/main");
  const [environment, setEnvironment] = useState("");
  const [issuer, setIssuer] = useState("");
  const [sub, setSub] = useState("");
  const [aud, setAud] = useState("");
  const [account, setAccount] = useState("");
  const [role, setRole] = useState("");
  const [access, setAccess] = useState<"read" | "write">("read");
  const [chosen, setChosen] = useState<string[]>(["dev"]);
  const [shown, setShown] = useState<string | null>(null);

  useEffect(() => {
    api
      .workloadInfo()
      .then((i) => setAudience(i.audience))
      .catch(() => setAudience(""));
  }, []);

  function binding(): Omit<api.MachineBinding, "createdBy" | "createdAt"> {
    const base = { id: id.trim(), stages: chosen, access };
    if (preset === "aws") return { ...base, kind: "aws", account: account.trim(), role: role.trim() };
    if (preset === "github") {
      const claims: Record<string, string> = { repository: repo.trim() };
      if (ref.trim()) claims.ref = ref.trim();
      if (environment.trim()) claims.environment = environment.trim();
      return { ...base, kind: "oidc", issuer: GITHUB, claims };
    }
    return {
      ...base,
      kind: "oidc",
      issuer: issuer.trim(),
      claims: { sub: sub.trim() },
      ...(aud.trim() ? { audience: aud.trim() } : {}),
    };
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    run(async () => {
      await api.upsertMachine(project, binding());
      setId("");
    });
  }

  const ready =
    id.trim() &&
    chosen.length > 0 &&
    (preset === "github" ? repo.includes("/") : preset === "oidc" ? issuer && sub : account && role);

  return (
    <div className="panel" style={{ marginTop: 28 }}>
      <div className="panel-head">
        <h2>Machine identities</h2>
      </div>
      <div className="panel-body">
        <p className="sub" style={{ margin: 0 }}>
          CI jobs and workloads log in with their own identity — a GitHub Actions or other OIDC
          token, or an AWS IAM role — and get a 15-minute token for exactly the stages bound here.
          Nothing long-lived is stored anywhere. Editing or removing a binding cuts off its tokens
          immediately.
          {audience && (
            <>
              {" "}
              Tokens must be requested for audience <code>{audience}</code>.
            </>
          )}
        </p>
      </div>
      {machines.length > 0 && (
        <ul className="list">
          {machines.map((m) => (
            <li key={m.id} style={{ flexWrap: "wrap" }}>
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="mono" style={{ fontSize: 14 }}>
                  {m.id}
                </div>
                <div style={{ fontSize: 12.5, color: "var(--ink-dim)", overflowWrap: "anywhere" }}>
                  {describe(m)}
                </div>
              </div>
              {m.stages.map((s) => (
                <span key={s} className="tag">
                  {s}
                </span>
              ))}
              <span className={`tag ${m.access === "write" ? "accent" : ""}`}>{m.access}</span>
              <button className="btn quiet" onClick={() => setShown(shown === m.id ? null : m.id)}>
                usage
              </button>
              {isOwner && (
                <button
                  className="btn quiet danger"
                  disabled={busy}
                  onClick={() => run(() => api.removeMachine(project, m.id))}
                >
                  remove
                </button>
              )}
              {shown === m.id && (
                <pre className="code" style={{ flexBasis: "100%", marginTop: 10 }}>
                  {usage(project, m, audience)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
      {isOwner && (
        <div className="panel-body" style={{ borderTop: "1px solid var(--line)" }}>
          <form onSubmit={submit}>
            <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
              <label className="field">
                <span>source</span>
                <select value={preset} onChange={(e) => setPreset(e.target.value as Preset)}>
                  <option value="github">GitHub Actions</option>
                  <option value="oidc">Other OIDC issuer (GitLab, Kubernetes, …)</option>
                  <option value="aws">AWS IAM role</option>
                </select>
              </label>
              <label className="field">
                <span>identity id</span>
                <input type="text" value={id} onChange={(e) => setId(e.target.value)} placeholder="deploy-ci" />
              </label>
            </div>

            {preset === "github" && (
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <label className="field">
                  <span>repository</span>
                  <input type="text" value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="acme/webapp" />
                </label>
                <label className="field">
                  <span>ref (optional, * allowed)</span>
                  <input type="text" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="refs/heads/main" />
                </label>
                <label className="field">
                  <span>environment (optional)</span>
                  <input
                    type="text"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    placeholder="production"
                  />
                </label>
              </div>
            )}

            {preset === "oidc" && (
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <label className="field">
                  <span>issuer</span>
                  <input
                    type="text"
                    value={issuer}
                    onChange={(e) => setIssuer(e.target.value)}
                    placeholder="https://gitlab.com"
                  />
                </label>
                <label className="field">
                  <span>sub pattern</span>
                  <input
                    type="text"
                    value={sub}
                    onChange={(e) => setSub(e.target.value)}
                    placeholder="project_path:acme/webapp:ref_type:branch:ref:main"
                  />
                </label>
                <label className="field">
                  <span>audience (optional)</span>
                  <input type="text" value={aud} onChange={(e) => setAud(e.target.value)} placeholder={audience} />
                </label>
              </div>
            )}

            {preset === "aws" && (
              <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                <label className="field">
                  <span>account id</span>
                  <input
                    type="text"
                    value={account}
                    onChange={(e) => setAccount(e.target.value)}
                    placeholder="123456789012"
                  />
                </label>
                <label className="field">
                  <span>role name</span>
                  <input type="text" value={role} onChange={(e) => setRole(e.target.value)} placeholder="webapp-task-role" />
                </label>
              </div>
            )}

            <div className="row" style={{ gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
              <label className="field">
                <span>access</span>
                <select value={access} onChange={(e) => setAccess(e.target.value as "read" | "write")}>
                  <option value="read">read — pull and decrypt</option>
                  <option value="write">write — also upload and delete</option>
                </select>
              </label>
              <button className="btn" style={{ marginBottom: 18 }} disabled={busy || !ready}>
                bind identity
              </button>
            </div>
            <StagePicker value={chosen.filter((s) => stages.includes(s))} onChange={setChosen} />
          </form>
        </div>
      )}
    </div>
  );
}
