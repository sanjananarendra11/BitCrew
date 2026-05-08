let currentTabUrl = "";

// Get current active tab URL
chrome.tabs.query(
  { active: true, currentWindow: true },
  function (tabs) {
    if (tabs.length > 0) {
      currentTabUrl = tabs[0].url || "";
      document.getElementById("current-url").innerText = currentTabUrl;
    }
  }
);

// Scan button click
document.getElementById("scanBtn").addEventListener("click", async () => {
  const resultDiv = document.getElementById("result");

  resultDiv.innerHTML = `
    <div class="loading">
      Scanning website...
    </div>
  `;

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    let pageContent = {
      hasPasswordField: false,
      formCount: 0,
      suspiciousWords: 0,
      hasExternalFormAction: false,
      hasRedirectScript: false,
      detectedBrands: []
    };

    // =========================================
    // Get content.js data safely
    // =========================================

    try {
      const responseFromContent = await chrome.tabs.sendMessage(
        tab.id,
        {
          action: "getPageContent"
        }
      );

      if (responseFromContent) {
        pageContent = responseFromContent;
      }

    } catch (err) {
      console.log("Content script unavailable:", err);
    }

    // =========================================
    // Backend API Call
    // =========================================

    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: currentTabUrl,
        content_data: pageContent
      })
    });

    const data = await response.json();

    console.log("FULL API RESPONSE:", data);

    if (data.error) {
      resultDiv.innerHTML = `
        <div class="error-box">
          ${data.error}
        </div>
      `;
      return;
    }

    // Safe fallback objects
    const layer1 = data.layer1 || {};
    const layer2 = data.layer2 || {
      confidence: 0,
      contributions: []
    };
    const layer3 = data.layer3 || {
      threat_type: "Safe Browsing",
      severity: "Low",
      explanations: []
    };

    // =========================================
    // Layer 1 HTML
    // =========================================

    let layer1HTML = "";

    Object.entries(layer1).forEach(([key, value]) => {
      layer1HTML += `
        <div class="row">
          <span>${key}</span>
          <span>${value}</span>
        </div>
      `;
    });

    const riskMeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #ff4fd8 ${(data.risk_score || 0) * 3.6}deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${data.risk_score || 0}%
          </div>
        </div>

        <div class="risk-label">
          ${
            (data.risk_score || 0) >= 80
              ? "CRITICAL RISK"
              : (data.risk_score || 0) >= 60
              ? "HIGH RISK"
              : (data.risk_score || 0) >= 30
              ? "MEDIUM RISK"
              : "LOW RISK"
          }
        </div>
      </div>
    `;

    // =========================================
    // Layer 2 HTML
    // =========================================

    const layer2MeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #00e5ff ${(layer2.confidence || 0) * 3.6}deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${layer2.confidence || 0}%
          </div>
        </div>

        <div class="risk-label">
          ML CONFIDENCE
        </div>
      </div>
    `;

    let contributionHTML = "";

    if ((layer2.contributions || []).length === 0) {
      contributionHTML = `
        <p class="safe-note">
          No major risk factors detected
        </p>
      `;
    } else {
      layer2.contributions.forEach(item => {
        const score = parseInt(
          (item.impact || "+0").replace("+", "")
        );

        contributionHTML += `
          <div class="contribution-box">
            <div class="contribution-top">
              <span class="feature-name">${item.name}</span>
              <span class="feature-score">${item.impact}</span>
            </div>

            <div class="bar-bg">
              <div
                class="bar-fill"
                style="width: ${Math.min(score * 2, 100)}%;">
              </div>
            </div>
          </div>
        `;
      });
    }

    // =========================================
    // Layer 3 HTML
    // =========================================

    const layer3MeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #ff4fd8 ${
                layer3.severity === "High"
                  ? 300
                  : layer3.severity === "Medium"
                  ? 220
                  : 120
              }deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${layer3.severity || "Low"}
          </div>
        </div>

        <div class="risk-label">
          THREAT SEVERITY
        </div>
      </div>
    `;

    let explanationHTML = "";

    if ((layer3.explanations || []).length === 0) {
      explanationHTML = `
        <p class="safe-note">
          No strong phishing indicators detected
        </p>
      `;
    } else {
      layer3.explanations.forEach(item => {
        explanationHTML += `
          <div class="contribution">
            <span>- ${item}</span>
          </div>
        `;
      });
    }

    // =========================================
    // Final UI
    // =========================================

    resultDiv.innerHTML = `
      <div class="dashboard">

        <!-- Layer 1 -->
        <div class="panel">
          <h2>Layer 1 - URL Analysis</h2>
          ${riskMeterHTML}
          ${layer1HTML}
        </div>

        <!-- Layer 2 -->
        <div class="panel">
          <h2>Layer 2 - ML Analysis</h2>

          <div class="prediction ${
            data.prediction === "Safe" ? "safe" : "phishing"
          }">
            ${data.prediction || "Safe"}
          </div>

          ${layer2MeterHTML}

          <h3>Feature Contributions</h3>
          ${contributionHTML}
        </div>

        <!-- Layer 3 -->
        <div class="panel">
          <h2>Layer 3 - Content Analysis + Intent Reasoning</h2>

          <div class="prediction ${
            data.prediction === "Safe" ? "safe" : "phishing"
          }">
            ${layer3.threat_type || "Safe Browsing"}
          </div>

          ${layer3MeterHTML}

          <h3>Why Flagged</h3>
          ${explanationHTML}
        </div>

        <!-- Final Verdict -->
        <div class="panel final-verdict">
          <h2>Final Security Verdict</h2>

          <div class="prediction ${
            data.prediction === "Safe" ? "safe" : "phishing"
          }">
            ${
              data.prediction === "Safe"
                ? "SAFE WEBSITE"
                : "PHISHING DETECTED"
            }
          </div>

          <div class="risk-meter">
            <div
              class="circle"
              style="
                background: conic-gradient(
                  ${
                    data.prediction === "Safe"
                      ? "#00ff9d"
                      : "#ff4fd8"
                  } ${(data.risk_score || 0) * 3.6}deg,
                  rgba(255,255,255,0.08) 0deg
                );
              "
            >
              <div class="inner-circle">
                ${layer2.confidence || 0}%
              </div>
            </div>

            <div class="risk-label">
              FINAL CONFIDENCE
            </div>
          </div>

          <div class="confidence">
            Threat Level:
            ${
              (data.risk_score || 0) >= 80
                ? "CRITICAL"
                : (data.risk_score || 0) >= 60
                ? "HIGH"
                : (data.risk_score || 0) >= 30
                ? "MEDIUM"
                : "LOW"
            }
          </div>

          <h3>Main Reason</h3>

          <div class="contribution">
            <span>
              ${
                (layer3.explanations || []).length > 0
                  ? layer3.explanations[0]
                  : "No major suspicious indicators detected"
              }
            </span>
          </div>
        </div>

      </div>
    `;

  } catch (error) {
    console.error(error);

    resultDiv.innerHTML = `
      <div class="error-box">
        Backend connection failed
      </div>
    `;
  }
});