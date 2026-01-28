export default function ReportCard({ report }) {
  if (!report) return null;

  function getRiskMeter(score) {
    if (score < 0.35) return { label: "Benign", blocks: 2 };
    if (score < 0.55) return { label: "Low", blocks: 3 };
    if (score < 0.70) return { label: "Suspicious", blocks: 4 };
    if (score < 0.85) return { label: "High", blocks: 5 };
    return { label: "Critical", blocks: 6 };
  }

  const { label, blocks } = getRiskMeter(report.final_score);

  return (
    <div
      style={{
        background: "#fff",
        border: "1px solid #ddd",
        borderRadius: "8px",
        padding: "20px",
        marginTop: "20px",
        width: "100%",
        display: "flex",
        flexDirection: "column",
        gap: "12px",
        boxShadow: "0 2px 6px rgba(0,0,0,0.05)"
      }}
    >
      <h2 style={{ margin: 0 }}>Output</h2>

      <div>
        <strong>Risk Score: </strong>
        {report.final_score}
      </div>

      {/* RISK METER BAR */}
      <div style={{ marginTop: "10px" }}>
        <strong>Risk Meter:</strong>

        <div
          style={{
            marginTop: "8px",
            display: "flex",
            gap: "4px"
          }}
        >
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              style={{
                height: "10px",
                width: "30px",
                background: i < blocks ? "#37dd00ff" : "#ddd",
                borderRadius: "3px",
                transition: "background 0.2s ease"
              }}
            />
          ))}
        </div>

        <div
          style={{
            marginTop: "6px",
            fontSize: "14px",
            color: "#444",
            fontFamily: "Consolas, monospace"
          }}
        >
          {label}
        </div>
      </div>

      <strong>Indicators:</strong>

      <pre
        style={{
          background: "#eee",
          padding: "14px",
          borderRadius: "6px",
          overflowX: "auto",
          fontSize: "14px",
          fontFamily: "Consolas, monospace"
        }}
      >
        {JSON.stringify(report.reasons, null, 2)}
      </pre>
    </div>
  );
}







