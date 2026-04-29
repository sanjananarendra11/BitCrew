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

    if (data.error) {
      resultDiv.innerHTML = `
        <div class="error-box">
          ${data.error}
        </div>
      `;
      return;
    }

    // Layer 1 HTML
    let layer1HTML = "";

    Object.entries(data.layer1).forEach(([key, value]) => {
      layer1HTML += `
        <div class="row">
          <span>${key}</span>
          <span>${value}</span>
        </div>
      `;
    });

    // Layer 1 Circular Meter
    const riskMeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #ff4fd8 ${data.risk_score * 3.6}deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${data.risk_score}%
          </div>
        </div>

        <div class="risk-label">
          ${
            data.risk_score >= 80
              ? "CRITICAL RISK"
              : data.risk_score >= 60
              ? "HIGH RISK"
              : data.risk_score >= 30
              ? "MEDIUM RISK"
              : "LOW RISK"
          }
        </div>
      </div>
    `;

    // Layer 2 Meter
    const layer2MeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #00e5ff ${data.layer2.confidence * 3.6}deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${data.layer2.confidence}%
          </div>
        </div>

        <div class="risk-label">
          ML CONFIDENCE
        </div>
      </div>
    `;

    // Layer 2 Contributions
    let contributionHTML = "";

    if (data.layer2.contributions.length === 0) {
      contributionHTML = `
        <p class="safe-note">
          No major risk factors detected
        </p>
      `;
    } else {
      data.layer2.contributions.forEach(item => {
        const score = parseInt(item.impact.replace("+", ""));

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

    // Layer 3 Meter
    const layer3MeterHTML = `
      <div class="risk-meter">
        <div
          class="circle"
          style="
            background: conic-gradient(
              #ff4fd8 ${
                data.layer3.severity === "High"
                  ? 300
                  : data.layer3.severity === "Medium"
                  ? 220
                  : 120
              }deg,
              rgba(255,255,255,0.08) 0deg
            );
          "
        >
          <div class="inner-circle">
            ${data.layer3.severity}
          </div>
        </div>

        <div class="risk-label">
          THREAT SEVERITY
        </div>
      </div>
    `;

    // Layer 3 Explanations
    let explanationHTML = "";

    if (data.layer3.explanations.length === 0) {
      explanationHTML = `
        <p class="safe-note">
          No strong phishing indicators detected
        </p>
      `;
    } else {
      data.layer3.explanations.forEach(item => {
        explanationHTML += `
          <div class="contribution">
            <span>- ${item}</span>
          </div>
        `;
      });
    }

    // Layer 3 Graphs
    let layer3GraphHTML = "";

    const layer3Features = [
      {
        name: "Password Field",
        value: pageContent.hasPasswordField ? 30 : 0,
        display: pageContent.hasPasswordField ? "Yes" : "No"
      },
      {
        name: "Forms Detected",
        value: pageContent.formCount * 10,
        display: pageContent.formCount
      },
      {
        name: "Suspicious Words",
        value: pageContent.suspiciousWords * 8,
        display: pageContent.suspiciousWords
      },
      {
        name: "External Form Action",
        value: pageContent.hasExternalFormAction ? 35 : 0,
        display: pageContent.hasExternalFormAction ? "Yes" : "No"
      },
      {
        name: "Redirect Script",
        value: pageContent.hasRedirectScript ? 20 : 0,
        display: pageContent.hasRedirectScript ? "Yes" : "No"
      }
    ];

    layer3Features.forEach(item => {
      layer3GraphHTML += `
        <div class="contribution-box">
          <div class="contribution-top">
            <span class="feature-name">${item.name}</span>
            <span class="feature-score">${item.display}</span>
          </div>

          <div class="bar-bg">
            <div
              class="bar-fill"
              style="width: ${Math.min(item.value * 2, 100)}%;">
            </div>
          </div>
        </div>
      `;
    });

    layer3GraphHTML += `
      <div class="row">
        <span>Detected Brands</span>
        <span>
          ${
            pageContent.detectedBrands.length > 0
              ? pageContent.detectedBrands.join(", ")
              : "None"
          }
        </span>
      </div>
    `;

    // FINAL UI
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
            ${data.prediction}
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
            ${data.layer3.threat_type}
          </div>

          ${layer3MeterHTML}

          <h3>Why Flagged</h3>
          ${explanationHTML}

          <br>

          ${layer3GraphHTML}
        </div>

        <!-- Final Security Verdict -->
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
                  } ${data.risk_score * 3.6}deg,
                  rgba(255,255,255,0.08) 0deg
                );
              "
            >
              <div class="inner-circle">
                ${data.layer2.confidence}%
              </div>
            </div>

            <div class="risk-label">
              FINAL CONFIDENCE
            </div>
          </div>

          <div class="confidence">
            Threat Level:
            ${
              data.risk_score >= 80
                ? "CRITICAL"
                : data.risk_score >= 60
                ? "HIGH"
                : data.risk_score >= 30
                ? "MEDIUM"
                : "LOW"
            }
          </div>

          <h3>Main Reason</h3>

          <div class="contribution">
            <span>
              ${
                data.layer3.explanations.length > 0
                  ? data.layer3.explanations[0]
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