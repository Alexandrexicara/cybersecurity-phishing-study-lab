const views = [...document.querySelectorAll(".view")];
const navItems = [...document.querySelectorAll(".nav-item")];
const titles = {overview:"Visão geral",phishing:"Análise de phishing",web:"Segurança web",awareness:"Conscientização",reports:"Relatórios"};
const API_BASE = "https://cybersecurity-phishing-study-lab.onrender.com";
const studentIdKey = "cyberlab-student-id";
let studentId = localStorage.getItem(studentIdKey);
if (!studentId) {
  studentId = crypto.randomUUID();
  localStorage.setItem(studentIdKey, studentId);
}
let completed = [];
try { completed = JSON.parse(localStorage.getItem("cyberlab-progress") || "[]"); } catch { completed = []; }
let syncTimer;
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
    const response = await fetch(`${API_BASE}/api/progress?studentId=${encodeURIComponent(studentId)}`);
    if (!response.ok) throw new Error("Falha ao carregar");
    const data = await response.json();
    completed = Array.isArray(data.completedModules) ? data.completedModules : [];
    localStorage.setItem("cyberlab-progress", JSON.stringify(completed));
    updateProgress();
    setSyncStatus("Progresso sincronizado com o banco de dados.");
  } catch {
    setSyncStatus("API indisponível no momento. O progresso fica temporariamente neste navegador.");
  }
}
async function saveProgress() {
  localStorage.setItem("cyberlab-progress", JSON.stringify(completed));
  updateProgress();
  setSyncStatus("Salvando progresso...");
  try {
    const response = await fetch(`${API_BASE}/api/progress`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ studentId, completedModules: completed })
    });
    if (!response.ok) throw new Error("Falha ao salvar");
    setSyncStatus("Progresso salvo no banco de dados.");
  } catch {
    setSyncStatus("Sem conexão com a API. O progresso permanece salvo neste navegador.");
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
updateProgress();
syncFromServer();
