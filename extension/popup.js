let currentTabUrl = "";

// Get current tab URL automatically
chrome.tabs.query(
  { active: true, currentWindow: true },
  function (tabs) {
    currentTabUrl = tabs[0].url;
    document.getElementById("current-url").innerText = currentTabUrl;
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
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        url: currentTabUrl
      })
    });

    const data = await response.json();

    // Handle backend errors
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

    // Layer 2 Contributions HTML
    let contributionHTML = "";

    if (data.layer2.contributions.length === 0) {
      contributionHTML = `
        <p class="safe-note">
          No major risk factors detected
        </p>
      `;
    } else {
      data.layer2.contributions.forEach(item => {
        contributionHTML += `
          <div class="contribution">
            <span>${item.name}</span>
            <span class="impact">${item.impact}</span>
          </div>
        `;
      });
    }

    // Final UI
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

      </div>
    `;

  } catch (error) {
    resultDiv.innerHTML = `
      <div class="error-box">
        Backend connection failed
      </div>
    `;
    console.error(error);
  }
});