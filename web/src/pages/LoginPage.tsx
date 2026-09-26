import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import { flags } from "../lib/flags";
import { useAuth } from "../state/auth";

export default function LoginPage({ mode = "login" }: { mode?: "login" | "signup" }) {
  const signup = mode === "signup";
  const { requestCode, verifyCode } = useAuth();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [stage, setStage] = useState<"email" | "code">("email");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submitEmail(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await requestCode(email, signup);
      setStage("code");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await verifyCode(email, code.trim());
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <div className="login">
        <p className="kicker">
          <Link to="/" style={{ color: "inherit", textDecoration: "none" }}>
            ← encrypted environment files
          </Link>
        </p>
        <p className="brand" style={{ marginTop: 0 }}>
          enclave<b>-envoy</b>
        </p>
        <p className="sub" style={{ marginBottom: 24 }}>
          {signup
            ? "Create an account with just your email. We send a one-time code to prove the address is yours — no password."
            : "Files are encrypted in this browser before they leave it. Sign in with a one-time code to continue."}
        </p>
        {error && <p className="error">{error}</p>}
        {stage === "email" ? (
          <form onSubmit={submitEmail} className="fade-in">
            <label className="field">
              <span>email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoFocus
                required
              />
            </label>
            <button className="btn primary" disabled={busy || !email}>
              {busy ? "sending…" : signup ? "create account" : "send login code"}
            </button>
            {flags.signup && (
              <p className="sub" style={{ marginTop: 16 }}>
                {signup ? (
                  <>
                    Already have an account? <Link to="/login">Sign in</Link>
                  </>
                ) : (
                  <>
                    New here? <Link to="/signup">Create an account</Link>
                  </>
                )}
              </p>
            )}
          </form>
        ) : (
          <form onSubmit={submitCode} className="fade-in">
            <p className="notice">
              {signup
                ? `A code is on its way to ${email}. Enter it to finish creating your account.`
                : `If ${email} is registered, a code is on its way.`}
            </p>
            <label className="field">
              <span>one-time code</span>
              <input
                type="text"
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="000000"
                autoFocus
                required
              />
            </label>
            <div className="row" style={{ alignItems: "center" }}>
              <button className="btn primary" disabled={busy || !code}>
                {busy ? "verifying…" : signup ? "verify & create account" : "verify"}
              </button>
              <button
                type="button"
                className="btn quiet"
                onClick={() => {
                  setStage("email");
                  setCode("");
                  setError(null);
                }}
              >
                use another email
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
