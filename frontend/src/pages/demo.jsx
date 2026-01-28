import { useState } from "react";
import axios from "axios";
import Layout from "../components/Layout";
import ScanPanel from "../components/ScanPanel";
import ReportCard from "../components/ReportCard";

export default function Demo() {
  const [report, setReport] = useState(null);

  const onSubmit = async (payload) => {
    const res = await axios.post("http://localhost:8000/api/scan/page", payload);
    setReport(res.data);
  };

  return (
    <Layout>
      <ScanPanel onSubmit={onSubmit} />
      <ReportCard report={report} />
    </Layout>
  );
}


