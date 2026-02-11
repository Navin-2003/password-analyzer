const passwordInput = document.getElementById("password");
const toggleButton = document.getElementById("toggle");
const copyButton = document.getElementById("copy");
const meterFill = document.getElementById("meter-fill");
const strengthLabel = document.getElementById("strength-label");
const checklist = document.getElementById("checklist");
const riskContainer = document.getElementById("risk");
const recommendations = document.getElementById("recommendations");
const scoreLabel = document.getElementById("score");
const entropyLabel = document.getElementById("entropy");
const breachButton = document.getElementById("breach");
const breachStatus = document.getElementById("breach-status");
const breachResult = document.getElementById("breach-result");
const breachDetail = document.getElementById("breach-detail");

const breachedPasswords = new Set([
  "123456",
  "password",
  "123456789",
  "qwerty",
  "12345678",
  "111111",
  "123123",
  "abc123",
  "qwerty123",
  "password1",
  "admin",
  "letmein",
  "welcome",
  "iloveyou",
  "000000",
  "football",
  "monkey",
  "dragon",
  "sunshine",
  "princess",
  "login",
  "starwars",
  "solo",
  "passw0rd",
  "master",
  "hello",
  "freedom",
  "whatever",
  "qazwsx",
  "trustno1",
  "aa123456",
  "mustang",
  "baseball",
  "shadow",
  "michael",
  "jordan",
  "superman",
  "bailey",
  "access",
  "batman",
  "liverpool",
  "jesus",
  "ninja",
  "adobe123",
  "photoshop",
  "1q2w3e4r",
  "1qaz2wsx",
  "password123",
  "changeme",
]);

const checklistItems = [
  { id: "length", label: "At least 12 characters" },
  { id: "upper", label: "Uppercase letter" },
  { id: "lower", label: "Lowercase letter" },
  { id: "number", label: "Number" },
  { id: "symbol", label: "Symbol" },
  { id: "spaces", label: "No leading or trailing spaces" },
  { id: "repeat", label: "Avoid repeated patterns" },
  { id: "sequence", label: "No obvious sequences" },
];

const sequencePattern = /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg|qwerty)/i;

const renderChecklist = () => {
  checklist.innerHTML = "";
  checklistItems.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.dataset.rule = item.id;
    const dot = document.createElement("span");
    dot.className = "status-dot";
    const text = document.createElement("span");
    text.textContent = item.label;
    listItem.append(dot, text);
    checklist.appendChild(listItem);
  });
};

const calculateEntropy = (password) => {
  if (!password) {
    return 0;
  }
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9\s]/.test(password)) pool += 32;
  if (/\s/.test(password)) pool += 1;
  const entropy = Math.log2(Math.pow(pool, password.length));
  return Number.isFinite(entropy) ? entropy : 0;
};

const assessPassword = (password) => {
  const trimmed = password.trim();
  const checks = {
    length: password.length >= 12,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /\d/.test(password),
    symbol: /[^A-Za-z0-9\s]/.test(password),
    spaces: trimmed === password,
    repeat: !/(.)\1{2,}/.test(password),
    sequence: !sequencePattern.test(password),
  };

  const entropy = calculateEntropy(password);
  let score = 0;
  score += checks.length ? 20 : 0;
  score += checks.upper ? 12 : 0;
  score += checks.lower ? 12 : 0;
  score += checks.number ? 12 : 0;
  score += checks.symbol ? 12 : 0;
  score += checks.spaces ? 8 : 0;
  score += checks.repeat ? 12 : 0;
  score += checks.sequence ? 12 : 0;
  score += Math.min(Math.round(entropy / 2), 20);
  score = Math.min(score, 100);

  return { checks, entropy: Math.round(entropy), score };
};

const strengthFromScore = (score) => {
  if (score >= 80) return { label: "Excellent", color: "var(--success)" };
  if (score >= 60) return { label: "Strong", color: "#10b981" };
  if (score >= 40) return { label: "Fair", color: "var(--warning)" };
  return { label: "Weak", color: "var(--danger)" };
};

const updateChecklist = (checks) => {
  checklist.querySelectorAll("li").forEach((item) => {
    const rule = item.dataset.rule;
    const dot = item.querySelector(".status-dot");
    const ok = checks[rule];
    dot.classList.toggle("ok", ok);
    item.querySelector("span:last-child").innerHTML = ok
      ? `<strong>${checklistItems.find((i) => i.id === rule).label}</strong>`
      : checklistItems.find((i) => i.id === rule).label;
  });
};

const updateRiskInsights = (password, checks) => {
  const risks = [];
  if (!password) {
    riskContainer.innerHTML = "Add a password to see risk insights.";
    return;
  }
  if (breachedPasswords.has(password.toLowerCase())) {
    risks.push("This password appears in a high-risk breached list.");
  }
  if (!checks.length) risks.push("Short passwords are easier to crack.");
  if (!checks.symbol) risks.push("Consider adding a symbol for more complexity.");
  if (!checks.repeat) risks.push("Repeated characters reduce strength.");
  if (!checks.sequence) risks.push("Sequences are easy to guess.");
  if (password.length > 0 && /[A-Za-z]/.test(password) && !/[0-9]/.test(password)) {
    risks.push("Add numbers to improve variety.");
  }
  if (risks.length === 0) {
    risks.push("No immediate risks detected. Keep monitoring for breaches.");
  }

  riskContainer.innerHTML = "";
  risks.forEach((risk) => {
    const card = document.createElement("div");
    card.className = "risk-card";
    card.textContent = risk;
    riskContainer.appendChild(card);
  });
};

const updateRecommendations = (password, checks) => {
  const tips = [];
  if (!password) {
    recommendations.textContent = "Recommendations will appear here.";
    return;
  }
  if (!checks.length) tips.push("Use a passphrase of 12+ characters.");
  if (!checks.upper || !checks.lower) tips.push("Mix uppercase and lowercase letters.");
  if (!checks.number) tips.push("Add at least one number.");
  if (!checks.symbol) tips.push("Include symbols like !, %, or #.");
  if (!checks.repeat) tips.push("Avoid repeating the same character.");
  if (!checks.sequence) tips.push("Avoid predictable sequences.");
  if (breachedPasswords.has(password.toLowerCase())) {
    tips.push("Choose a password that is not on common breach lists.");
  }
  if (tips.length === 0) {
    tips.push("Great work! Save it in a password manager.");
  }

  recommendations.innerHTML = "";
  tips.forEach((tip) => {
    const item = document.createElement("div");
    item.textContent = `• ${tip}`;
    recommendations.appendChild(item);
  });
};

const updateUI = () => {
  const password = passwordInput.value;
  const { checks, entropy, score } = assessPassword(password);
  updateChecklist(checks);
  updateRiskInsights(password, checks);
  updateRecommendations(password, checks);

  entropyLabel.textContent = `${entropy} bits`;
  scoreLabel.textContent = `${score} / 100`;

  if (!password) {
    strengthLabel.textContent = "Add a password to begin.";
    meterFill.style.width = "0%";
    meterFill.style.background = "var(--danger)";
    breachStatus.textContent = "Not checked";
    breachResult.textContent = "";
    breachDetail.textContent = "Offline list only.";
    return;
  }

  const strength = strengthFromScore(score);
  strengthLabel.textContent = `${strength.label} strength`;
  meterFill.style.width = `${score}%`;
  meterFill.style.background = strength.color;
  breachStatus.textContent = breachedPasswords.has(password.toLowerCase())
    ? "Flagged offline"
    : "Not flagged offline";
};

const toSha1 = async (value) => {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
};

const checkBreach = async () => {
  const password = passwordInput.value;
  if (!password) {
    breachResult.textContent = "Enter a password first.";
    return;
  }

  breachButton.disabled = true;
  breachButton.textContent = "Checking...";
  breachDetail.textContent = "Using HIBP k-anonymity range lookup.";

  try {
    const sha1 = await toSha1(password);
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) {
      throw new Error("Range lookup failed");
    }
    const text = await response.text();
    const match = text
      .split("\n")
      .map((line) => line.trim().split(":"))
      .find(([hashSuffix]) => hashSuffix === suffix);
    if (match) {
      breachStatus.textContent = "Breached";
      breachResult.textContent = `Found ${Number(match[1]).toLocaleString()} times in breaches.`;
    } else {
      breachStatus.textContent = "Not found";
      breachResult.textContent = "No breach record found in the range response.";
    }
  } catch (error) {
    breachResult.textContent = "Unable to reach the breach API. Check your connection.";
    breachStatus.textContent = "Unknown";
    breachDetail.textContent = "Fallback to offline list only.";
  } finally {
    breachButton.disabled = false;
    breachButton.textContent = "Run breach check";
  }
};

passwordInput.addEventListener("input", updateUI);

toggleButton.addEventListener("click", () => {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  toggleButton.textContent = isHidden ? "Hide" : "Show";
});

copyButton.addEventListener("click", async () => {
  if (!passwordInput.value) {
    strengthLabel.textContent = "Nothing to copy.";
    return;
  }
  await navigator.clipboard.writeText(passwordInput.value);
  strengthLabel.textContent = "Password copied to clipboard.";
});

breachButton.addEventListener("click", checkBreach);

renderChecklist();
updateUI();
