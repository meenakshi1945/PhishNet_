import React, { useState } from "react";
const animationStyles = `
@keyframes fadeSlideIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
`;
export default function ScanPanel() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const sanitizeInput = (value) => value.replace(/[\r\n\t]/g, " ").trim();
  const handlePasteAsPlainText = (e) => {
    e.preventDefault();
    const pastedText = e.clipboardData.getData("text");
    setUrl(sanitizeInput(pastedText));
  };
  const handleScan = async () => {
    if (!url.trim()) {
      setError("No input detected. Please enter a URL to proceed scanning.");
      setResult(null);
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch(
        "http://localhost:8000/api/scan/scan-light",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url }),
        }
      );
      if (!response.ok) {
        throw new Error("Scan failed");
      }
      const data = await response.json();
      setResult(data.result);
    } catch (err) {
      setError("Failed to scan the URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <>
      <style>{animationStyles}</style>
      <section
        style={{
          width: "100%",
          maxWidth: "520px",
          margin: "0 auto",
          background: "var(--bg-card)",
          padding: "32px",
          borderRadius: "var(--radius-lg)",
          border: "1px solid var(--border-soft)",
          boxShadow: "0 25px 60px rgba(0,0,0,0.45)",
        }}
      >
        <h2 style={{ marginBottom: "6px", textAlign: "center" }}>PhishNet</h2>
        <p style={{ marginBottom: "28px", textAlign: "center" }}>
          Learn whether a URL is safe or potentially malicious.
        </p>
        <input
          type="text"
          placeholder="Paste a URL to scan"
          value={url}
          onChange={(e) => setUrl(sanitizeInput(e.target.value))}
          onPaste={handlePasteAsPlainText}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="none"
          spellCheck={false}
          style={{
            width: "100%",
            padding: "14px",
            borderRadius: "var(--radius-md)",
            marginBottom: "16px",
          }}
        />
        <button
          onClick={handleScan}
          disabled={loading}
          style={{
            width: "100%",
            padding: "14px",
            borderRadius: "var(--radius-md)",
            background: "var(--accent)",
            color: "#ffffff",
            fontSize: "1rem",
            fontWeight: 500,
          }}
          onMouseOver={(e) =>
            (e.target.style.background = "var(--accent-hover)")
          }
          onMouseOut={(e) =>
            (e.target.style.background = "var(--accent)")
          }
        >
          {loading ? "Scanning…" : "Scan URL"}
        </button>
        <p
          style={{
            marginTop: "10px",
            fontSize: "0.85rem",
            color: "#9ca3af",
            textAlign: "center",
          }}
        >
          Pasted input is handled as plain text only and analyzed by our detection engine.
        </p>
        {error && (
          <p style={{ color: "#f87171", marginTop: "16px", textAlign: "center" }}>
            {error}
          </p>
        )}
        {result && (
          <div
            style={{
              marginTop: "28px",
              padding: "18px",
              borderRadius: "var(--radius-md)",
              background: "#10131a",
              border: "1px solid var(--border-soft)",
              animation: "fadeSlideIn 0.35s ease-out",
            }}
          >
            <p style={{ fontWeight: 500 }}>
              {result.label === "phishing"
                ? "🚨 Phishing Detected"
                : "✅ Safe URL"}
            </p>
            <p style={{ marginTop: "6px" }}>
              Confidence: {(result.confidence * 100).toFixed(2)}%
            </p>
            {result.risk_level && (
              <p style={{ marginTop: "6px" }}>
                Risk level: {String(result.risk_level).toUpperCase()}
              </p>
            )}
            {result.recommended_action && (
              <p style={{ marginTop: "6px" }}>
                Recommended action: {String(result.recommended_action).replace(/_/g, " ")}
              </p>
            )}
            {result.reasons && result.reasons.length > 0 && (
              <ul style={{ marginTop: "10px", paddingLeft: "20px" }}>
                {result.reasons.map((reason, index) => (
                  <li key={index}>{reason}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>
    </>
  );
}









