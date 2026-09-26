import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import * as api from "../lib/api";

interface Session {
  token: string;
  email: string;
  access: Record<string, string[]>;
}

interface AuthContextValue {
  session: Session | null;
  requestCode: (email: string, signup?: boolean) => Promise<void>;
  verifyCode: (email: string, code: string) => Promise<void>;
  refreshAccess: () => Promise<void>;
  logout: () => void;
}

const STORAGE_KEY = "enclave.session";

const AuthContext = createContext<AuthContextValue | null>(null);

function loadSession(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    // Drop expired tokens eagerly (exp is the JWT's second segment).
    const payload = JSON.parse(atob(s.token.split(".")[1])) as { exp: number };
    if (payload.exp * 1000 < Date.now()) return null;
    return s;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => {
    const s = loadSession();
    api.setToken(s?.token ?? null);
    return s;
  });

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    api.setToken(null);
    setSession(null);
  }, []);

  useEffect(() => {
    api.setOnUnauthorized(logout);
    return () => api.setOnUnauthorized(null);
  }, [logout]);

  const requestCode = useCallback(async (email: string, signup = false) => {
    await api.authRequest(email, signup);
  }, []);

  const verifyCode = useCallback(async (email: string, code: string) => {
    const out = await api.authVerify(email, code);
    const s: Session = { token: out.token, email: out.email, access: out.access };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
    api.setToken(s.token);
    setSession(s);
  }, []);

  const refreshAccess = useCallback(async () => {
    const out = await api.whoami();
    setSession((prev) => {
      if (!prev) return prev;
      const next = { ...prev, access: out.access };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const value = useMemo(
    () => ({ session, requestCode, verifyCode, refreshAccess, logout }),
    [session, requestCode, verifyCode, refreshAccess, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
