import { describe, expect, it } from "vitest";
import { DOCS, renderDoc } from "./docs";

describe("concept docs", () => {
  it("renders every doc with a title heading", () => {
    for (const doc of DOCS) expect(renderDoc(doc)).toMatch(/^<h1>/);
  });

  it("turns links between the markdown files into /docs routes", () => {
    const html = DOCS.map(renderDoc).join("\n");
    expect(html).toContain('href="/docs/machine-identities"');
    expect(html).not.toMatch(/href="[^"]*\.md"/);
  });
});
