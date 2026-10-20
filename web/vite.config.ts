import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // /docs bundles ../docs/concept/*.md; let the dev server read the repo root.
  server: { fs: { allow: [".."] } },
});
