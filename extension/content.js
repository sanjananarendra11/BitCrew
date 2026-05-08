function extractPageContent() {
  const pageData = {
    hasPasswordField: false,
    formCount: 0,
    suspiciousWords: 0,
    hasExternalFormAction: false,
    hasRedirectScript: false,
    detectedBrands: []
  };

  try {
    // Safe body check
    if (!document.body) {
      return pageData;
    }

    // 1. Password fields
    const passwordFields = document.querySelectorAll(
      'input[type="password"]'
    );

    pageData.hasPasswordField = passwordFields.length > 0;

    // 2. Forms count
    const forms = document.querySelectorAll("form");
    pageData.formCount = forms.length;

    // 3. External form action
    forms.forEach(form => {
      const action = form.getAttribute("action");

      if (
        action &&
        action.startsWith("http") &&
        !action.includes(window.location.hostname)
      ) {
        pageData.hasExternalFormAction = true;
      }
    });

    // 4. Suspicious keywords
    const suspiciousKeywords = [
      "login",
      "verify",
      "password",
      "secure",
      "account",
      "confirm",
      "update",
      "bank",
      "payment",
      "signin",
      "wallet",
      "alert",
      "suspended"
    ];

    const bodyText = (
      document.body.innerText || ""
    ).toLowerCase();

    suspiciousKeywords.forEach(word => {
      if (bodyText.includes(word)) {
        pageData.suspiciousWords++;
      }
    });

    // 5. Redirect detection
    const scripts = document.querySelectorAll("script");

    scripts.forEach(script => {
      const text = (
        script.innerText || ""
      ).toLowerCase();

      if (
        text.includes("window.location") ||
        text.includes("location.href")
      ) {
        pageData.hasRedirectScript = true;
      }
    });

    // 6. Brand detection
    const knownBrands = [
      "google",
      "paypal",
      "amazon",
      "facebook",
      "microsoft",
      "apple",
      "icloud",
      "bank"
    ];

    knownBrands.forEach(brand => {
      if (bodyText.includes(brand)) {
        pageData.detectedBrands.push(brand);
      }
    });

  } catch (error) {
    console.log("Content extraction error:", error);
  }

  return pageData;
}

chrome.runtime.onMessage.addListener(
  function (request, sender, sendResponse) {
    if (request.action === "getPageContent") {
      sendResponse(extractPageContent());
      return true;
    }
  }
);