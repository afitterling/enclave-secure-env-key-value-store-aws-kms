import { Link, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { flags } from "./lib/flags";
import { useAuth } from "./state/auth";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import ProjectsPage from "./pages/ProjectsPage";
import ProjectPage from "./pages/ProjectPage";
import ProjectSettingsPage from "./pages/ProjectSettingsPage";
import TeamsPage from "./pages/TeamsPage";
import TeamPage from "./pages/TeamPage";

export default function App() {
  const { session, logout } = useAuth();

  if (!session) {
    return (
      <Routes>
        <Route path="/" element={flags.landing ? <LandingPage /> : <LoginPage />} />
        <Route path="/login" element={<LoginPage />} />
        {flags.signup && <Route path="/signup" element={<LoginPage mode="signup" />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    );
  }

  return (
    <div className="shell">
      <header className="topbar">
        <Link to="/" className="brand">
          enclave<b>-envoy</b>
        </Link>
        <nav>
          <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
            Projects
          </NavLink>
          {flags.teams && (
            <NavLink to="/teams" className={({ isActive }) => (isActive ? "active" : "")}>
              Teams
            </NavLink>
          )}
        </nav>
        <div className="who">
          <span>{session.email}</span>
          <button className="btn quiet" onClick={logout}>
            log out
          </button>
        </div>
      </header>
      <Routes>
        <Route path="/" element={<ProjectsPage />} />
        <Route path="/projects/:project" element={<ProjectPage />} />
        <Route path="/projects/:project/settings" element={<ProjectSettingsPage />} />
        {flags.teams && <Route path="/teams" element={<TeamsPage />} />}
        {flags.teams && <Route path="/teams/:team" element={<TeamPage />} />}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  );
}
