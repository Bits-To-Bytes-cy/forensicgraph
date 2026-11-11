import { Link, Route, Routes } from "react-router-dom";

function Dashboard() {
  return (
    <main>
      <p className="eyebrow">ENGINEERING FOUNDATION · PHASE 0</p>
      <h1>ForensicGraph</h1>
      <p className="lede">
        Evidence-centric digital forensics and incident reconstruction platform.
      </p>
      <section className="status-card">
        <span className="status-dot" />
        <div>
          <strong>Platform shell ready</strong>
          <p>Investigation modules will be introduced in later phases.</p>
        </div>
      </section>
    </main>
  );
}

function App() {
  return (
    <>
      <header>
        <Link to="/" className="brand">
          ForensicGraph
        </Link>
        <span className="phase-label">Phase 0</span>
      </header>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </>
  );
}

export default App;
