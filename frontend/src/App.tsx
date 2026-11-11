import { Link, Route, Routes } from "react-router-dom";
import CaseCreate from "./pages/CaseCreate";
import CaseDashboard from "./pages/CaseDashboard";
import CaseDetails from "./pages/CaseDetails";

function Dashboard() {
  return <CaseDashboard organizationId="demo-organization" />;
}

function App() {
  return (
    <>
      <header>
        <Link to="/" className="brand">
          ForensicGraph
        </Link>
        <span className="phase-label">Phase 1B · Cases</span>
      </header>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route
          path="/organizations/:organizationId/cases/new"
          element={<CaseCreate />}
        />
        <Route path="/cases/:caseId" element={<CaseDetails />} />
      </Routes>
    </>
  );
}

export default App;
