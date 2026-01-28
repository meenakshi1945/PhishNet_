import React, { useState } from "react";
const scanLightweight = async (url) => {
  const response = await fetch("https://phishnet-api.onrender.com/api/scan/scan-light", ...)
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

  return await response.json();
};

export default function ScanPanel() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    if (!url) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanLightweight(url);
      setResult(data.result);
    } catch (err) {
      setError("Failed to scan URL");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
return (
  <div
    style={{
      background: "#020617",
      padding: "32px",
      borderRadius: "16px",
      width: "100%",
      maxWidth: "420px",
      color: "#e5e7eb",
      boxShadow: "0 20px 40px rgba(0,0,0,0.6)",
    }}
  >
    <h2 style={{ marginBottom: "8px" }}>PhishNet URL Scan</h2>
    <p style={{ marginBottom: "20px", color: "#9ca3af" }}>
      Check whether a URL is malicious or safe.
    </p>

    <input
      type="text"
      placeholder="Enter URL to scan"
      value={url}
      onChange={(e) => setUrl(e.target.value)}
      style={{
        width: "100%",
        padding: "12px",
        marginBottom: "12px",
        borderRadius: "8px",
        border: "1px solid #334155",
        background: "#020617",
        color: "#e5e7eb",
      }}
    />

    <button
      onClick={handleScan}
      disabled={loading}
      style={{
        width: "100%",
        padding: "12px",
        borderRadius: "8px",
        background: "#4f46e5",
        color: "#ffffff",
        border: "none",
        fontWeight: "600",
        cursor: "pointer",
      }}
    >
      {loading ? "Scanning..." : "Scan"}
    </button>

    {error && (
      <p style={{ color: "#f87171", marginTop: "12px" }}>
        {error}
      </p>
    )}

    {result && (
      <div
        style={{
          marginTop: "20px",
          padding: "16px",
          borderRadius: "10px",
          background:
            result.label === "phishing"
              ? "#3f1d1d"
              : "#052e16",
        }}
      >
        <p style={{ fontWeight: "600" }}>
          {result.label === "phishing"
            ? "🚨 Phishing Detected"
            : "✅ Safe URL"}
        </p>

        <p style={{ marginTop: "6px" }}>
          Confidence: {(result.confidence * 100).toFixed(2)}%
        </p>

        {result.reasons.length > 0 && (
          <ul style={{ marginTop: "8px", paddingLeft: "20px" }}>
            {result.reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    )}
  </div>
);

}








