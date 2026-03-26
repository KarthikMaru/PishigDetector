const urlInput = document.getElementById("url-input");
const detectorForm = document.getElementById("detector-form");
const sampleButtons = document.querySelectorAll(".sample-link");
const scoreValue = document.getElementById("score-value");
const scoreRing = document.getElementById("score-ring");
const statusTag = document.getElementById("status-tag");
const summaryTitle = document.getElementById("summary-title");
const summaryText = document.getElementById("summary-text");
const hostnameValue = document.getElementById("hostname-value");
const protocolValue = document.getElementById("protocol-value");
const categoryValue = document.getElementById("category-value");
const findingsList = document.getElementById("findings-list");

const shortenerDomains = new Set([
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "tiny.cc",
]);

const suspiciousTlds = new Set([
  "zip",
  "top",
  "xyz",
  "click",
  "gq",
  "work",
  "country",
  "fit",
  "support",
  "live",
]);

const baitKeywords = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "password",
  "wallet",
  "banking",
  "invoice",
  "recover",
];

function normalizeUrl(rawValue) {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    throw new Error("Enter a URL to scan.");
  }

  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function isIpAddress(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function humanizeLevel(score) {
  if (score < 25) {
    return { label: "Low risk", className: "low", category: "Likely legitimate" };
  }

  if (score < 55) {
    return { label: "Medium risk", className: "medium", category: "Needs caution" };
  }

  return { label: "High risk", className: "high", category: "Potential phishing" };
}

function addFinding(findings, severity, title, description, weight = 0) {
  findings.push({ severity, title, description, weight });
}

function analyzeUrl(rawValue) {
  const normalized = normalizeUrl(rawValue);
  const parsed = new URL(normalized);
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const full = `${hostname}${pathname}${parsed.search.toLowerCase()}`;
  const hostnameParts = hostname.split(".").filter(Boolean);
  const findings = [];
  let score = 0;

  if (parsed.protocol === "https:") {
    addFinding(
      findings,
      "good",
      "HTTPS is present",
      "Encrypted transport is a positive sign, although phishing sites can also use HTTPS."
    );
  } else {
    score += 20;
    addFinding(
      findings,
      "danger",
      "HTTP instead of HTTPS",
      "A login or payment page using plain HTTP is a strong warning sign.",
      20
    );
  }

  if (hostname.startsWith("xn--")) {
    score += 25;
    addFinding(
      findings,
      "danger",
      "Punycode domain detected",
      "Internationalized domains can be abused to mimic trusted brands with lookalike characters.",
      25
    );
  }

  if (isIpAddress(hostname)) {
    score += 30;
    addFinding(
      findings,
      "danger",
      "Direct IP address host",
      "Legitimate branded websites rarely ask users to sign in through a bare IP address.",
      30
    );
  }

  if (shortenerDomains.has(hostname)) {
    score += 30;
    addFinding(
      findings,
      "danger",
      "Known URL shortener",
      "Shortened links hide the real destination, which makes phishing attempts harder to verify.",
      30
    );
  }

  if (hostnameParts.length > 4) {
    score += 15;
    addFinding(
      findings,
      "warn",
      "Many subdomains",
      "Long hostnames can be used to bury a fake brand name inside extra subdomains.",
      15
    );
  }

  if (hostname.includes("@")) {
    score += 25;
    addFinding(
      findings,
      "danger",
      "Unexpected @ symbol",
      "The @ character can mask the true destination in misleading URLs.",
      25
    );
  }

  if ((hostname.match(/-/g) || []).length >= 2) {
    score += 12;
    addFinding(
      findings,
      "warn",
      "Heavy hyphen use",
      "Phishing domains often stitch together brand-like words with multiple hyphens.",
      12
    );
  }

  if ((hostname.match(/\d/g) || []).length >= 4) {
    score += 10;
    addFinding(
      findings,
      "warn",
      "Many digits in hostname",
      "Extra numbers in a login-style domain can indicate disposable or auto-generated infrastructure.",
      10
    );
  }

  if (parsed.port) {
    score += 8;
    addFinding(
      findings,
      "warn",
      "Custom port in URL",
      "Unexpected port numbers can indicate a non-standard or hastily deployed site.",
      8
    );
  }

  const tld = hostnameParts.at(-1) || "";
  if (suspiciousTlds.has(tld)) {
    score += 15;
    addFinding(
      findings,
      "warn",
      "Higher-risk top-level domain",
      "This TLD appears more often in low-trust campaigns and throwaway domains.",
      15
    );
  }

  const keywordHits = baitKeywords.filter((keyword) => full.includes(keyword));
  if (keywordHits.length >= 2) {
    const weight = Math.min(22, 8 + keywordHits.length * 4);
    score += weight;
    addFinding(
      findings,
      "warn",
      "Credential or urgency bait",
      `The URL contains terms like ${keywordHits.join(", ")}, which are frequently used in phishing lures.`,
      weight
    );
  }

  if (normalized.length > 90) {
    score += 10;
    addFinding(
      findings,
      "warn",
      "Very long URL",
      "Long links can hide the important parts of the destination and make visual inspection harder.",
      10
    );
  }

  if (findings.length === 1 && parsed.protocol === "https:") {
    addFinding(
      findings,
      "good",
      "No major heuristic flags found",
      "This URL does not match common phishing patterns checked by this demo."
    );
  }

  score = Math.min(score, 100);
  findings.sort((left, right) => right.weight - left.weight);

  return {
    parsed,
    hostname,
    score,
    findings,
    ...humanizeLevel(score),
  };
}

function renderFindings(findings) {
  findingsList.innerHTML = "";

  findings.forEach((finding) => {
    const item = document.createElement("li");
    item.className = `finding ${finding.severity}`;
    item.innerHTML = `
      <h3>${finding.title}</h3>
      <p>${finding.description}</p>
    `;
    findingsList.appendChild(item);
  });
}

function renderResult(result) {
  const degrees = `${Math.round((result.score / 100) * 360)}deg`;
  const ringColor =
    result.className === "low"
      ? "var(--good)"
      : result.className === "medium"
        ? "var(--warn)"
        : "var(--danger)";

  scoreValue.textContent = String(result.score);
  scoreRing.style.background = `conic-gradient(${ringColor} ${degrees}, rgba(99, 116, 135, 0.18) ${degrees})`;
  statusTag.textContent = result.label;
  statusTag.className = `status-tag ${result.className}`;
  summaryTitle.textContent =
    result.className === "low"
      ? "This link shows low-risk signals."
      : result.className === "medium"
        ? "This link deserves a closer look."
        : "This link shows strong phishing signals.";
  summaryText.textContent =
    result.className === "low"
      ? "Nothing obviously malicious was found by these heuristics, but you should still verify the domain and context."
      : result.className === "medium"
        ? "Some patterns here are commonly seen in suspicious URLs. Verify the destination before entering credentials."
        : "Multiple phishing indicators were found. Avoid signing in or submitting personal information until the URL is independently verified.";

  hostnameValue.textContent = result.hostname;
  protocolValue.textContent = result.parsed.protocol.replace(":", "").toUpperCase();
  categoryValue.textContent = result.category;
  renderFindings(result.findings);
}

function renderError(message) {
  scoreValue.textContent = "0";
  scoreRing.style.background =
    "conic-gradient(var(--neutral) 0deg, rgba(99, 116, 135, 0.18) 0deg)";
  statusTag.textContent = "Input error";
  statusTag.className = "status-tag neutral";
  summaryTitle.textContent = "That URL could not be parsed.";
  summaryText.textContent = message;
  hostnameValue.textContent = "-";
  protocolValue.textContent = "-";
  categoryValue.textContent = "-";
  findingsList.innerHTML =
    '<li class="finding finding-empty">Use a full domain name or paste a standard website URL.</li>';
}

detectorForm.addEventListener("submit", (event) => {
  event.preventDefault();

  try {
    renderResult(analyzeUrl(urlInput.value));
  } catch (error) {
    renderError(error.message);
  }
});

sampleButtons.forEach((button) => {
  button.addEventListener("click", () => {
    urlInput.value = button.dataset.url || "";
    detectorForm.requestSubmit();
  });
});
