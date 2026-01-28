import ScanPanel from "../components/ScanPanel";

export default function Home() {
  return (
    <main
      style={{
        minHeight: "100vh",
        background: "radial-gradient(ellipse at top, #1b1f2a 0%, #0f1115 60%)",
        padding: "80px 20px",
      }}
    >
      <div
        style={{
          maxWidth: "900px",
          margin: "0 auto",
        }}
      >
        {/* Header */}
        <header style={{ marginBottom: "48px" }}>
          <h1 style={{ fontSize: "2.2rem", marginBottom: "10px" }}>
            PhishNet
          </h1>
          <p style={{ maxWidth: "600px" }}>
            A lightweight phishing detection system that analyzes URLs using
            machine learning and security heuristics.
          </p>
        </header>

        {/* Main tool */}
        <ScanPanel />

        {/* Info section */}
        <section
          style={{
            marginTop: "56px",
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "24px",
          }}
        >
          <InfoCard
            title="Machine Learning"
            text="Uses a trained lightweight model to classify URLs as phishing or safe."
          />
          <InfoCard
            title="Explainable Output"
            text="Provides confidence scores and human-readable reasons for decisions."
          />
          <InfoCard
            title="Fast & Lightweight"
            text="Designed for quick analysis without heavy infrastructure."
          />
        </section>
      </div>
    </main>
  );
}

function InfoCard({ title, text }) {
  return (
    <div
      style={{
        background: "#151822",
        border: "1px solid #252935",
        borderRadius: "14px",
        padding: "20px",
      }}
    >
      <h3 style={{ fontSize: "1rem", marginBottom: "6px" }}>{title}</h3>
      <p style={{ fontSize: "0.95rem" }}>{text}</p>
    </div>
  );
}


