document.getElementById("scanBtn").addEventListener("click", async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.scripting.executeScript(
    {
      target: { tabId: tab.id },
      function: getPageData,
    },
    (results) => {
      if (!results || !results[0]) {
        document.getElementById("result").innerText =
          "Could not extract page data.";
        return;
      }

      let pageData = results[0].result;
      let text = pageData.text;
      let hiddenIframeCount = pageData.hiddenIframes;
      let url = tab.url;

      let analysis = calculateHybridRisk(text, url, hiddenIframeCount);

      let resultBox = document.getElementById("result");

      resultBox.innerText =
        "Risk Score: " +
        (analysis.risk_score * 100).toFixed(2) +
        "%\nStatus: " +
        analysis.label +
        "\n\nSignals:\n" +
        analysis.signals.join("\n");

      if (analysis.label === "Malicious") {
        resultBox.style.background = "#7f1d1d";
      } else if (analysis.label === "Suspicious") {
        resultBox.style.background = "#78350f";
      } else {
        resultBox.style.background = "#14532d";
      }
    }
  );
});


// Extract page text + hidden iframe info
function getPageData() {
  let text = document.body.innerText;

  let hiddenIframes = 0;
  let iframes = document.querySelectorAll("iframe");

  iframes.forEach(frame => {
    let style = window.getComputedStyle(frame);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      frame.width === "0" ||
      frame.height === "0"
    ) {
      hiddenIframes++;
    }
  });

  return {
    text: text,
    hiddenIframes: hiddenIframes
  };
}


function calculateHybridRisk(text, url, hiddenIframeCount) {
  let signals = [];
  let score = 0;

  let lowerText = text.toLowerCase();

  const maliciousKeywords = [
    "bypass",
    "ignore previous instructions",
    "admin access",
    "developer mode",
    "system override",
    "exploit",
    "authentication bypass",
    "confidential data",
    "unauthorized access",
    "payload",
    "malware",
    "phishing"
  ];

  // 🔹 Content risk
  maliciousKeywords.forEach(keyword => {
    if (lowerText.includes(keyword)) {
      score += 0.05;
      signals.push("Keyword detected: " + keyword);
    }
  });

  // 🔹 Suspicious script patterns
  if (
    lowerText.includes("eval(") ||
    lowerText.includes("unescape(") ||
    lowerText.includes("document.write(") ||
    lowerText.includes("atob(")
  ) {
    score += 0.25;
    signals.push("Suspicious script pattern detected");
  }

  // 🔹 Base64 / obfuscation detection
  let base64Pattern = /[A-Za-z0-9+/]{100,}={0,2}/;
  if (base64Pattern.test(text)) {
    score += 0.25;
    signals.push("Possible obfuscated / encoded script detected");
  }

  // 🔹 Hidden iframe detection
  if (hiddenIframeCount > 0) {
    score += 0.3;
    signals.push("Hidden iframe(s) detected: " + hiddenIframeCount);
  }

  // 🔹 Infrastructure risk (HTTP errors)
  if (
    lowerText.includes("503 service unavailable") ||
    lowerText.includes("500 internal server error") ||
    lowerText.includes("502 bad gateway")
  ) {
    score += 0.2;
    signals.push("Server error page detected");
  }

  // 🔹 HTTPS check
  if (!url.startsWith("https")) {
    score += 0.15;
    signals.push("Not using HTTPS");
  }

  // 🔹 IP-based URL
  let ipPattern = /https?:\/\/\d+\.\d+\.\d+\.\d+/;
  if (ipPattern.test(url)) {
    score += 0.2;
    signals.push("IP-based URL detected");
  }

  // 🔹 Suspicious domain structure
  let domain = new URL(url).hostname;
  if ((domain.match(/-/g) || []).length > 3) {
    score += 0.15;
    signals.push("Suspicious domain structure");
  }

  // Normalize score
  score = Math.min(score, 1);

  let label = "Safe";
  if (score > 0.5) {
    label = "Malicious";
  } else if (score > 0.25) {
    label = "Suspicious";
  }

  return {
    risk_score: score,
    label: label,
    signals: signals.length ? signals : ["No major risk indicators detected"]
  };
}