/**
 * Feature toggles, flipped in sst.config.ts (`features`) and applied at the
 * next deploy. Enforced server-side here; the web UI additionally hides
 * disabled features (its copy is baked into the build as VITE_FEATURES).
 * Unknown/missing flags fail closed.
 */

export type FeatureName = "landing" | "teams" | "fileDelete" | "signup";

export function featureEnabled(name: FeatureName): boolean {
  try {
    return Boolean((JSON.parse(process.env.FEATURES ?? "{}") as Record<string, unknown>)[name]);
  } catch {
    return false;
  }
}
