/** Feature flags & edition, baked into the build from sst.config.ts
 * (VITE_FEATURES / VITE_EDITION). The server enforces the same flags — hiding
 * here is UX, not security. For local experiments a partial override can be
 * set: localStorage["enclave.flags"] = '{"teams":false}'. */

export interface Flags {
  landing: boolean;
  teams: boolean;
  fileDelete: boolean;
  signup: boolean;
  machineIdentities: boolean;
}

const defaults: Flags = { landing: true, teams: true, fileDelete: true, signup: false, machineIdentities: false };

function parse(raw: string | undefined | null): Partial<Flags> {
  try {
    return raw ? (JSON.parse(raw) as Partial<Flags>) : {};
  } catch {
    return {};
  }
}

export const flags: Flags = {
  ...defaults,
  ...parse(import.meta.env.VITE_FEATURES as string | undefined),
  ...parse(typeof localStorage !== "undefined" ? localStorage.getItem("enclave.flags") : null),
};

export const edition: "opensource" | "enterprise" =
  (import.meta.env.VITE_EDITION as "opensource" | "enterprise" | undefined) ?? "enterprise";
