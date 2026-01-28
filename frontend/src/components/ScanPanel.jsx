import React, { useState } from "react";

/* Animation styles */
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

  const handleScan = async () => {
    if (!url.trim()) {
      setError("Please enter a valid URL.");
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
          background: "var(--bg-card)",
          padding: "32px",
          borderRadius: "var(--radius-lg)",
          border: "1px solid var(--border-soft)",
          boxShadow: "0 25px 60px rgba(0,0,0,0.45)",
        }}
      >
        {/* Header */}
        <h2 style={{ marginBottom: "6px" }}>PhishNet</h2>
        <p style={{ marginBottom: "28px" }}>
          Learn whether a URL is safe or potentially malicious.
        </p>

        {/* Input */}
        <input
          type="text"
          placeholder="Paste a URL to scan"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            width: "100%",
            padding: "14px",
            borderRadius: "var(--radius-md)",
            marginBottom: "16px",
          }}
        />

        {/* Button */}
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

        {/* Micro-copy */}
        <p
          style={{
            marginTop: "10px",
            fontSize: "0.85rem",
            color: "#9ca3af",
            textAlign: "center",
          }}
        >
          URLs are analyzed securely using our detection engine.
        </p>

        {/* Error */}
        {error && (
          <p style={{ color: "#f87171", marginTop: "16px" }}>
            {error}
          </p>
        )}

        {/* Result */}
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









