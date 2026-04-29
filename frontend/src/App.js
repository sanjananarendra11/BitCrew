import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scanURL = async () => {
    if (!url) {
      alert("Enter a URL");
      return;
    }

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
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          url: inputURL
        })
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

  const getPredictionColor = () => {
    if (!result) return "#00e5ff";
    return result.prediction === "Safe"
      ? "#00ff9d"
      : "#ff4d4d";
  };

  const getThreatLevel = () => {
    if (!result) return "LOW";

    if (result.risk_score >= 80) return "CRITICAL";
    if (result.risk_score >= 60) return "HIGH";
    if (result.risk_score >= 30) return "MEDIUM";
    return "LOW";
  };

  const getSeverityDegrees = () => {
    if (!result?.layer3?.severity) return 120;

    if (result.layer3.severity === "High") return 300;
    if (result.layer3.severity === "Medium") return 220;
    return 120;
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

      {/* Scanner */}
      {loading && <div className="scanner"></div>}

      {/* Error */}
      {error && (
        <p style={{ color: "#ff4d4d", marginTop: "20px" }}>
          {error}
        </p>
      )}

      {/* RESULTS */}
      {result && result.layer1 && (
        <div className="dashboard">

          {/* ========================= */}
          {/* Layer 1 */}
          {/* ========================= */}
          <div className="panel">
            <h2>Layer 1 – URL Analysis</h2>

            <div className="risk-meter">
  <div
    className="circle"
    style={{
      background: `conic-gradient(
        #00e5ff ${(result.risk_score || 0) * 3.6}deg,
        rgba(255,255,255,0.08) 0deg
      )`
    }}
  >
    <div className="inner-circle">
      {result.risk_score || 0}%
    </div>
  </div>

  <div className="risk-label">
    URL RISK SCORE
  </div>
</div>

            {Object.entries(result.layer1 || {}).map(([key, value]) => (
              <div className="row" key={key}>
                <span>{key}</span>
                <span>{String(value)}</span>
              </div>
            ))}
          </div>

          {/* ========================= */}
          {/* Layer 2 */}
          {/* ========================= */}
          <div className="panel">
            <h2>Layer 2 – ML Analysis</h2>

            <div
              className="prediction"
              style={{ color: getPredictionColor() }}
            >
              {result.prediction}
            </div>

            <div className="risk-meter">
  <div
    className="circle"
    style={{
      background: `conic-gradient(
        #00ff9d ${(result.layer2?.confidence || 0) * 3.6}deg,
        rgba(255,255,255,0.08) 0deg
      )`
    }}
  >
    <div className="inner-circle">
      {result.layer2?.confidence || 0}%
    </div>
  </div>

  <div className="risk-label">
    ML CONFIDENCE
  </div>
</div>

            <h4>Feature Contributions</h4>

            {result.layer2?.contributions?.length > 0 ? (
              result.layer2.contributions.map((item, index) => (
                <div className="contribution-box" key={index}>

                  <div className="contribution-top">
                    <span className="feature-name">
                      {item.name}
                    </span>
                    <span className="feature-score">
                      {item.impact}
                    </span>
                  </div>

                  <div className="bar-bg">
                    <div
                      className="bar-fill"
                      style={{
                        width: `${Math.min(
                          parseInt(item.impact.replace("+", "")) * 2,
                          100
                        )}%`
                      }}
                    ></div>
                  </div>

                </div>
              ))
            ) : (
              <p>No major risk factors detected</p>
            )}
          </div>

          {/* ========================= */}
          {/* Layer 3 */}
          {/* ========================= */}
          <div className="panel">
            <h2>Layer 3 – Content Analysis + Intent Reasoning</h2>

            <div
              className="prediction"
              style={{ color: getPredictionColor() }}
            >
              {result.layer3?.threat_type || "Safe Browsing"}
            </div>

            {/* Circular Severity Meter */}
            <div className="risk-meter">

              <div
                className="circle"
                style={{
                  background: `conic-gradient(
                    #ff4fd8 ${getSeverityDegrees()}deg,
                    rgba(255,255,255,0.08) 0deg
                  )`
                }}
              >
                <div className="inner-circle">
                  {result.layer3?.severity || "Low"}
                </div>
              </div>

              <div className="risk-label">
                THREAT SEVERITY
              </div>

            </div>

            <h4>Why Flagged</h4>

            {result.layer3?.explanations?.length > 0 ? (
              result.layer3.explanations.map((item, index) => (
                <div className="contribution" key={index}>
                  <span>• {item}</span>
                </div>
              ))
            ) : (
              <p>No strong phishing indicators detected</p>
            )}
          </div>

          {/* ========================= */}
          {/* Final Security Verdict */}
          {/* ========================= */}
          <div className="panel">
            <h2>Final Security Verdict</h2>

            <div
              className="prediction"
              style={{ color: getPredictionColor() }}
            >
              {result.prediction === "Safe"
                ? "SAFE WEBSITE"
                : "PHISHING DETECTED"}
            </div>

            <div className="risk-score">
              Final Confidence: {result.layer2?.confidence ?? 0}%
            </div>

            <div className="risk-score">
              Threat Level: {getThreatLevel()}
            </div>

            <h4>Main Reason</h4>

            <div className="contribution">
              <span>
                {result.layer3?.explanations?.length > 0
                  ? result.layer3.explanations[0]
                  : "No major suspicious indicators detected"}
              </span>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}

export default App;