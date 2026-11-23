const views = [...document.querySelectorAll(".view")];
const navItems = [...document.querySelectorAll(".nav-item")];
const titles = {overview:"Visão geral",phishing:"Análise de phishing",web:"Segurança web",awareness:"Conscientização",reports:"Relatórios"};
const API_BASE = "https://cybersecurity-phishing-study-lab.onrender.com";
const AUTH_KEY = "cyberlab-session-token";
let authToken = sessionStorage.getItem(AUTH_KEY) || "";
let completed = [];
let appStarted = false;

function authHeaders(extra = {}) {
  return { ...extra, ...(authToken ? { Authorization: "Bearer " + authToken } : {}) };
}
async function api(path, options = {}) {
  const headers = authHeaders(options.headers || {});
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const response = await fetch(API_BASE + path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Não foi possível concluir a operação.");
  return data;
}
function setAuthFeedback(message, isError = false) {
  const node = document.getElementById("auth-feedback");
  node.textContent = message;
  node.classList.toggle("error", isError);
}
function unlockApp(email) {
  document.body.classList.add("authenticated");
  document.getElementById("auth-gate").hidden = true;
  document.getElementById("signed-in-email").textContent = email || "Estudante";
  if (!appStarted) {
    appStarted = true;
    updateProgress();
    syncFromServer();
  }
}
function lockApp() {
  document.body.classList.remove("authenticated");
  document.getElementById("auth-gate").hidden = false;
  appStarted = false;
}
async function checkExistingSession() {
  if (!authToken) return lockApp();
  try {
    const result = await api("/api/auth/me");
    unlockApp(result.user.email);
  } catch {
    authToken = "";
    sessionStorage.removeItem(AUTH_KEY);
    lockApp();
  }
}

document.getElementById("auth-login").addEventListener("click", async () => {
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value;
  if (!email || !password) return setAuthFeedback("Informe seu e-mail e sua senha.", true);
  const button = document.getElementById("auth-login");
  button.disabled = true;
  setAuthFeedback("Validando seu acesso...");
  try {
    const result = await api("/api/auth/login", { method:"POST", body:JSON.stringify({email,password}) });
    authToken = result.token;
    sessionStorage.setItem(AUTH_KEY, authToken);
    document.getElementById("auth-password").value = "";
    setAuthFeedback("");
    unlockApp(result.user.email);
  } catch (error) {
    setAuthFeedback(error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("auth-request").addEventListener("click", async () => {
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value;
  if (!email || !password) return setAuthFeedback("Informe seu e-mail autorizado e crie uma senha com pelo menos 10 caracteres.", true);
  if (password.length < 10) return setAuthFeedback("A senha precisa ter pelo menos 10 caracteres.", true);

  // Open both destinations during the user's click gesture to reduce mobile popup blocking.
  const whatsappWindow = window.open("about:blank", "_blank");
  const emailWindow = window.open("about:blank", "_blank");
  const button = document.getElementById("auth-request");
  button.disabled = true;
  setAuthFeedback("Gerando seus dois links individuais...");
  document.getElementById("auth-link-actions").hidden = true;
  document.getElementById("auth-link-actions").classList.remove("visible");
  try {
    const result = await api("/api/auth/request-verification", {
      method:"POST", body:JSON.stringify({email,password})
    });
    if (whatsappWindow) whatsappWindow.location.href = result.whatsappUrl;
    if (emailWindow) emailWindow.location.href = result.emailUrl;
    document.getElementById("auth-whatsapp-link").href = result.whatsappUrl;
    document.getElementById("auth-email-link").href = result.emailUrl;
    document.getElementById("auth-link-actions").hidden = false;
    document.getElementById("auth-link-actions").classList.add("visible");
    setAuthFeedback("Os dois links foram gerados. Se algum aplicativo não abriu, use os links abaixo. Toque em Enviar dentro de cada aplicativo. O primeiro link confirmado libera o acesso e invalida o outro.");
  } catch (error) {
    if (whatsappWindow) whatsappWindow.close();
    if (emailWindow) emailWindow.close();
    setAuthFeedback(error.message, true);
  } finally {
    button.disabled = false;
  }
});

document.getElementById("auth-logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method:"POST" }); } catch {}
  authToken = "";
  sessionStorage.removeItem(AUTH_KEY);
  completed = [];
  lockApp();
  setAuthFeedback("Você saiu do Security Lab.");
});

function updateProgress() {
  const value = Math.round(completed.length / 2 * 100);
  document.getElementById("progress-number").textContent = Math.min(value, 100) + "%";
}
function setSyncStatus(message) {
  const status = document.getElementById("sync-status");
  if (status) status.textContent = message;
}
async function syncFromServer() {
  try {
    const data = await api("/api/progress");
    completed = Array.isArray(data.completedModules) ? data.completedModules : [];
    updateProgress();
    setSyncStatus("Progresso sincronizado com sua conta.");
  } catch (error) {
    setSyncStatus(error.message === "Faça login para continuar." ? "Entre novamente para sincronizar." : "Não foi possível sincronizar agora.");
  }
}
async function saveProgress() {
  updateProgress();
  setSyncStatus("Salvando progresso...");
  try {
    const data = await api("/api/progress", {
      method:"PUT",
      body:JSON.stringify({completedModules:completed})
    });
    completed = Array.isArray(data.completedModules) ? data.completedModules : completed;
    setSyncStatus("Progresso salvo no banco de dados.");
  } catch (error) {
    setSyncStatus(error.message);
  }
}
function markCompleted(moduleName) {
  if (!completed.includes(moduleName)) {
    completed.push(moduleName);
    saveProgress();
  }
}
function showView(name) {
  views.forEach(v => v.classList.toggle("active-view", v.id === name));
  navItems.forEach(b => b.classList.toggle("active", b.dataset.view === name));
  document.getElementById("page-title").textContent = titles[name] || "Visão geral";
  window.scrollTo({ top: 0, behavior: "smooth" });
}
navItems.forEach(b => b.addEventListener("click", () => showView(b.dataset.view)));
document.querySelectorAll("[data-go]").forEach(b => b.addEventListener("click", () => showView(b.dataset.go)));
document.getElementById("check-phishing").addEventListener("click", () => {
  const selected = [...document.querySelectorAll("#phishing-choices input:checked")].map(i => i.value).sort();
  const expected = ["request", "sender", "urgency"];
  const ok = JSON.stringify(selected) === JSON.stringify(expected);
  const feedback = document.getElementById("phishing-feedback");
  feedback.textContent = ok ? "Correto! Você identificou os três sinais de alerta." : "Revise: remetente incomum, urgência e solicitação inesperada são sinais de alerta.";
  if (ok) markCompleted("phishing");
});
document.querySelectorAll(".scenario-option").forEach(b => b.addEventListener("click", () => {
  const feedback = document.getElementById("scenario-feedback");
  const correct = b.dataset.correct === "true";
  feedback.textContent = correct ? "Boa decisão! Use sempre canais oficiais que você já conhece." : "Não é a opção mais segura. Evite links inesperados e procure o canal oficial.";
  if (correct) markCompleted("awareness");
}));
checkExistingSession();
