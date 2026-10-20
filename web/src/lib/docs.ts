import { marked, type Tokens } from "marked";
import overview from "../../../docs/concept/README.md?raw";
import machineIdentities from "../../../docs/concept/machine-identities.md?raw";
import workloadDelivery from "../../../docs/concept/workload-delivery.md?raw";
import ciem from "../../../docs/concept/ciem.md?raw";
import cloudRunner from "../../../docs/concept/cloud-runner.md?raw";

/**
 * Concept docs rendered on /docs. The markdown in docs/concept/ is the single
 * source: it is bundled at build time (?raw), so the page always matches the
 * deployed code. The input is our own repository content, never user data,
 * which is why the rendered HTML is not sanitized.
 */

export interface Doc {
  slug: string;
  title: string;
  markdown: string;
}

export const DOCS: Doc[] = [
  { slug: "", title: "Overview", markdown: overview },
  { slug: "machine-identities", title: "Machine identities", markdown: machineIdentities },
  { slug: "workload-delivery", title: "Delivering secrets to a workload", markdown: workloadDelivery },
  // Enterprise edition only: these two files exist on the enterprise branch.
  { slug: "ciem", title: "Entitlement management (CIEM)", markdown: ciem },
  { slug: "cloud-runner", title: "Cloud runner", markdown: cloudRunner },
];

const slugs = new Set(DOCS.map((d) => d.slug));

// Links between the markdown files (`machine-identities.md`) become routes.
function rewriteHref(href: string): string {
  const m = /^(?:\.\/)?([\w-]+)\.md(#.*)?$/.exec(href);
  if (!m) return href;
  const slug = m[1] === "README" ? "" : m[1];
  return slugs.has(slug) ? `/docs${slug ? `/${slug}` : ""}${m[2] ?? ""}` : href;
}

marked.use({
  gfm: true,
  walkTokens(token) {
    if (token.type === "link") (token as Tokens.Link).href = rewriteHref((token as Tokens.Link).href);
  },
});

export function renderDoc(doc: Doc): string {
  return marked.parse(doc.markdown, { async: false }) as string;
}
