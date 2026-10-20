import { useEffect, useMemo, type MouseEvent } from "react";
import { Link, NavLink, Navigate, useNavigate, useParams } from "react-router-dom";
import { DOCS, renderDoc } from "../lib/docs";

/**
 * Public concept documentation (docs/concept/*.md). Reachable signed in or
 * not; `standalone` adds the landing-style header for visitors.
 */
export default function DocsPage({ standalone = false }: { standalone?: boolean }) {
  const { slug = "" } = useParams();
  const navigate = useNavigate();
  const doc = DOCS.find((d) => d.slug === slug);
  const html = useMemo(() => (doc ? renderDoc(doc) : ""), [doc]);

  useEffect(() => {
    if (doc) document.title = `${doc.title} · enclave-envoy docs`;
    window.scrollTo(0, 0);
  }, [doc]);

  if (!doc) return <Navigate to="/docs" replace />;

  // Internal links inside the rendered markdown navigate without a reload;
  // external ones open in a new tab.
  function onClick(e: MouseEvent<HTMLElement>) {
    const a = (e.target as HTMLElement).closest("a");
    if (!a || e.metaKey || e.ctrlKey || e.shiftKey) return;
    const href = a.getAttribute("href") ?? "";
    if (href.startsWith("/")) {
      e.preventDefault();
      navigate(href);
    } else if (/^https?:/.test(href)) {
      a.target = "_blank";
      a.rel = "noreferrer";
    }
  }

  const body = (
    <div className="docs fade-in">
      <nav className="docs-nav" aria-label="documentation">
        <p className="kicker">concept</p>
        {DOCS.map((d) => (
          <NavLink key={d.slug} to={`/docs${d.slug ? `/${d.slug}` : ""}`} end>
            {d.title}
          </NavLink>
        ))}
      </nav>
      <article className="prose" onClick={onClick} dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  );

  if (!standalone) return body;
  return (
    <div className="landing">
      <header className="land-top">
        <Link to="/" className="brand" style={{ textDecoration: "none" }}>
          enclave<b>-envoy</b>
        </Link>
        <div className="spacer" />
        <Link className="btn" to="/login">
          sign in
        </Link>
      </header>
      {body}
    </div>
  );
}
