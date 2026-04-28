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
    // =========================================
    // STEP 1 → Get current active tab
    // =========================================

    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    // =========================================
    // STEP 2 → Get Layer 3 content data
    // =========================================

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

    console.log("Layer 3 Data:", pageContent);

    // =========================================
    // STEP 3 → Send URL + content data to Flask
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

    if (data.error) {
      resultDiv.innerHTML = `
        <div class="error-box">
          ${data.error}
        </div>
      `;
      return;
    }

    // =========================================
    // LAYER 1 HTML
    // =========================================

    let layer1HTML = "";

    Object.entries(data.layer1).forEach(([key, value]) => {
      layer1HTML += `
        <div class="row">
          <span>${key}</span>
          <span>${value}</span>
        </div>
      `;
    });

    // =========================================
    // LAYER 2 HTML
    // =========================================

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
              style="width: ${score * 2}px;">
            </div>
          </div>

        </div>
      `;
    });
    }

    // =========================================
    // LAYER 3 HTML
    // Threat Type + Explainability
    // =========================================

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

    let layer3HTML = "";

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
      layer3HTML += `
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

layer3HTML += `
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

    // =========================================
    // FINAL DASHBOARD UI
    // =========================================

    resultDiv.innerHTML = `
      <div class="dashboard">

        <!-- Layer 1 -->
        <div class="panel">
          <h2>Layer 1 - URL Analysis</h2>

          <div class="main-score">
            Risk Score: ${data.risk_score}
          </div>

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

          <div class="confidence">
            Confidence: ${data.layer2.confidence}%
          </div>

          <h3>Feature Contributions</h3>

          ${contributionHTML}
        </div>

        <!-- Layer 3 -->
        <div class="panel">
          <h2>Layer 3 - Content Analysis + Intent Reasoning</h2>

          ${layer3HTML}
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