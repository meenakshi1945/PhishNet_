export default function Layout({ children }) {
  return (
    <div
      style={{
        width: "90%",
        maxWidth: "800px",
        margin: "40px auto",
        fontFamily: "Arial, sans-serif"
      }}
    >
      <h1>PhishNet</h1>
      <p style={{ color: "#666", marginBottom: "20px" }}>
        Hybrid Phishing Detection
      </p>
      {children}
    </div>
  );
}






