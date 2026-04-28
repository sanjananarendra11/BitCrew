import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scanURL = async () => {
    if (!url) return alert("Enter a URL");

    let inputURL = url;
    if (!inputURL.startsWith("http")) {
      inputURL = "https://" + inputURL;
    }

    try {
      setLoading(true);
      setResult(null);
      setError("");

      const res = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: inputURL }),
      });

      const data = await res.json();
      console.log("API Response:", data);

      if (data.error) {
        setError(data.error);
      } else {
        setResult(data);
      }
    } catch (err) {
      console.error(err);
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const getColor = () => {
    if (!result) return "#00e5ff";
    return result.prediction === "Safe" ? "#00ff9d" : "#ff4d4d";
  };

  return (
    <div className="app">
      <h1 className="title">PhishGuard</h1>

      {/* INPUT */}
      <div className="input-box">
        <input
          type="text"
          placeholder="Paste suspicious URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button onClick={scanURL}>
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {/* SCANNING ANIMATION */}
      {loading && <div className="scanner"></div>}

      {/* ERROR MESSAGE */}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {/* RESULT DASHBOARD */}
      {result && result.layer1 && (
        <div className="dashboard">

          {/* 🔷 LAYER 1 — URL ANALYSIS */}
          <div className="panel">
            <h2>Layer 1 — URL Analysis</h2>

            <div className="risk-score">
              Risk: {result.risk_score ?? 0}
            </div>

            {Object.entries(result.layer1 || {}).map(([key, value]) => (
              <div className="row" key={key}>
                <span>{key}</span>
                <span>{value}</span>
              </div>
            ))}
          </div>

          {/* 🔷 LAYER 2 — ML ANALYSIS */}
          <div className="panel">
            <h2>Layer 2 — ML Analysis</h2>

            <div
              className="prediction"
              style={{ color: getColor() }}
            >
              {result.prediction} (
              {result.layer2?.confidence ?? 0}% confidence)
            </div>

            <h4>Feature Contributions</h4>

            {result.layer2?.contributions?.length > 0 ? (
              result.layer2.contributions.map((item, index) => (
                <div className="contribution" key={index}>
                  <span>{item.name}</span>
                  <span className="risk">{item.impact}</span>
                </div>
              ))
            ) : (
              <p>No major risk factors detected</p>
            )}
          </div>

        </div>
      )}
    </div>
  );
}

export default App;