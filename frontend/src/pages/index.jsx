import ScanPanel from "../components/ScanPanel";

export default function Home() {
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0f172a",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <ScanPanel />
    </div>
  );
}

