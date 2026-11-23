const views = [...document.querySelectorAll(".view")];
const navItems = [...document.querySelectorAll(".nav-item")];
const titles = {recon:"Central de operações",overview:"Visão geral",phishing:"Análise de phishing",web:"Segurança web",awareness:"Conscientização",reports:"Relatórios",tools:"Ferramentas"};
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

function analyzeUrl(raw) {
  const input = String(raw || "").trim();
  if (!input) throw new Error("Informe um endereço para analisar.");
  if (/\s/.test(input)) throw new Error("O endereço contém espaços. Confira e tente novamente.");
  let parsed;
  try { parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : "https://" + input); }
  catch { throw new Error("Não foi possível interpretar esse endereço. Confira o formato."); }
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Somente endereços HTTP ou HTTPS podem ser analisados.");
  const host = parsed.hostname.toLowerCase();
  const flags = [];
  if (parsed.protocol !== "https:") flags.push("Conexão sem HTTPS: os dados não têm proteção TLS durante o transporte.");
  if (parsed.username || parsed.password) flags.push("O endereço contém usuário ou senha antes do domínio, um artifício frequentemente usado para confundir.");
  if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--"))) flags.push("O domínio usa codificação Punycode; confira se há caracteres visualmente parecidos.");
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) flags.push("O destino usa endereço IP em vez de um nome de domínio comum.");
  if (host.split(".").length > 4) flags.push("O domínio possui muitos subdomínios; confirme qual é o domínio registrável.");
  if (/(login|signin|verify|secure|account|update|password|wallet|support)/i.test(parsed.pathname + parsed.search)) flags.push("O caminho contém termos frequentemente usados em páginas de autenticação ou verificação. Isso, sozinho, não prova fraude.");
  if (/(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)/i.test(host)) flags.push("O domínio parece ser um encurtador; o destino final não foi verificado.");
  if (host.length > 45) flags.push("O nome do host é longo; confira cuidadosamente a grafia.");
  if (/\.(zip|mov|click|top|xyz|work|support)$/i.test(host)) flags.push("A extensão do domínio merece verificação adicional; extensões, isoladamente, não determinam fraude.");
  if (!flags.length) flags.push("Nenhum dos indicadores simples configurados foi encontrado. Isso não garante que o endereço seja legítimo.");
  const high = flags.some(x => /usuário ou senha|Punycode|encurtador|endereço IP/i.test(x));
  const medium = flags.length >= 2 || parsed.protocol !== "https:";
  return {url:parsed.href,host,flags,level:high?"Atenção elevada":medium?"Revisar com cuidado":"Poucos sinais detectados"};
}
const runUrlCheck = document.getElementById("run-url-check");
if (runUrlCheck) runUrlCheck.addEventListener("click", () => {
  const resultNode = document.getElementById("url-check-result");
  const feedback = document.getElementById("url-check-feedback");
  try {
    const result = analyzeUrl(document.getElementById("url-to-check").value);
    resultNode.replaceChildren();
    const heading = document.createElement("h3"); heading.textContent = result.level;
    const domain = document.createElement("p"); domain.textContent = "Host analisado: " + result.host;
    const list = document.createElement("ul");
    result.flags.forEach(flag => { const li=document.createElement("li"); li.textContent=flag; list.append(li); });
    const disclaimer = document.createElement("p"); disclaimer.className="muted"; disclaimer.textContent="Análise heurística local. Nenhuma conexão foi feita com o endereço. Não substitui antivírus, reputação de domínio ou análise profissional.";
    resultNode.append(heading,domain,list,disclaimer);
    resultNode.hidden = false;
    feedback.textContent = "Análise concluída no navegador.";
    api("/api/reports",{method:"POST",body:JSON.stringify({kind:"url-analysis",title:"Análise de URL: "+result.host,details:result})}).catch(error=>{feedback.textContent += " Relatório não salvo: "+error.message;});
  } catch(error) {
    resultNode.hidden = true;
    feedback.textContent = error.message;
  }
});
const clearUrlCheck = document.getElementById("clear-url-check");
if (clearUrlCheck) clearUrlCheck.addEventListener("click", () => {
  document.getElementById("url-to-check").value = "";
  document.getElementById("url-check-result").hidden = true;
  document.getElementById("url-check-feedback").textContent = "";
});


const runDomainCheck = document.getElementById("run-domain-check");
if (runDomainCheck) runDomainCheck.addEventListener("click", async () => {
  const feedback = document.getElementById("domain-check-feedback");
  const resultNode = document.getElementById("domain-check-result");
  runDomainCheck.disabled = true;
  feedback.textContent = "Consultando DNS...";
  resultNode.hidden = true;
  try {
    const data = await api("/api/tools/domain-check", {method:"POST",body:JSON.stringify({domain:document.getElementById("domain-to-check").value})});
    resultNode.replaceChildren();
    const heading=document.createElement("h3"); heading.textContent=data.resolved?"Domínio resolvido":"Sem resolução DNS";
    const domain=document.createElement("p"); domain.textContent="Domínio: "+data.domain;
    const list=document.createElement("ul");
    (data.addresses.length?data.addresses:data.warnings).forEach(value=>{const li=document.createElement("li");li.textContent=value;list.append(li);});
    const note=document.createElement("p");note.className="muted";note.textContent=data.note;
    resultNode.append(heading,domain,list,note); resultNode.hidden=false;
    feedback.textContent="Consulta concluída.";
    await api("/api/reports",{method:"POST",body:JSON.stringify({kind:"dns-check",title:"Consulta DNS: "+data.domain,details:data})});
  } catch(error) { feedback.textContent=error.message; }
  finally { runDomainCheck.disabled=false; }
});
const loadReports = document.getElementById("load-security-reports");
if (loadReports) loadReports.addEventListener("click", async () => {
  const list=document.getElementById("security-reports-list");
  list.replaceChildren();
  try {
    const data=await api("/api/reports");
    if(!data.reports.length){const p=document.createElement("p");p.textContent="Nenhum relatório salvo ainda.";list.append(p);return;}
    data.reports.forEach(report=>{
      const item=document.createElement("article");
      const title=document.createElement("b");title.textContent=report.title;
      const date=document.createElement("p");date.textContent=new Date(report.created_at).toLocaleString("pt-BR");
      const kind=document.createElement("p");kind.textContent="Tipo: "+report.kind;
      item.append(title,date,kind);list.append(item);
    });
  } catch(error) { const p=document.createElement("p");p.textContent=error.message;list.append(p); }
});

checkExistingSession();

function initReconTools(){
 const validDomain = value => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value);
 const output = (id,data) => { const el=document.getElementById(id); if(el) el.textContent=typeof data==="string"?data:JSON.stringify(data,null,2); };
 const save = (kind,title,details) => api("/api/reports",{method:"POST",body:JSON.stringify({kind,title,details})}).catch(e=>console.warn("Relatório não salvo:",e.message));
 const bind = (buttonId,fn) => document.getElementById(buttonId)?.addEventListener("click",async e=>{const b=e.currentTarget;b.disabled=true;try{await fn();}catch(err){output(b.dataset.output||"op-dns-result","Erro: "+err.message);}finally{b.disabled=false;}});
 bind("op-dns-run",async()=>{const domain=document.getElementById("op-dns-domain").value.trim().toLowerCase();if(!validDomain(domain))throw Error("Informe um domínio público válido.");output("op-dns-result","Consultando registros DNS...");const types=["A","AAAA","MX","NS","TXT","CAA","CNAME"];const records=await Promise.all(types.map(async type=>{const r=await fetch("https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(domain)+"&type="+type,{headers:{accept:"application/dns-json"}});if(!r.ok)throw Error("Falha DNS "+r.status);const j=await r.json();return {type,status:j.Status,answers:(j.Answer||[]).map(x=>x.data)};}));const result={domain,source:"Cloudflare DNS over HTTPS",checkedAt:new Date().toISOString(),records};output("op-dns-result",result);await save("dns-lookup","DNS: "+domain,result);});
 bind("op-rdap-run",async()=>{const domain=document.getElementById("op-rdap-domain").value.trim().toLowerCase();if(!validDomain(domain))throw Error("Informe um domínio válido.");output("op-rdap-result","Consultando RDAP...");const r=await fetch("https://rdap.org/domain/"+encodeURIComponent(domain),{headers:{accept:"application/rdap+json"}});if(!r.ok)throw Error("RDAP indisponível: "+r.status);const j=await r.json();const result={domain:j.ldhName||domain,status:j.status||[],events:j.events||[],nameservers:(j.nameservers||[]).map(n=>n.ldhName),source:"RDAP"};output("op-rdap-result",result);await save("rdap","Registro: "+domain,result);});
 bind("op-ct-run",async()=>{const domain=document.getElementById("op-ct-domain").value.trim().toLowerCase().replace(/^\*\./,"");if(!validDomain(domain))throw Error("Informe um domínio válido.");output("op-ct-result","Consultando Certificate Transparency...");const r=await fetch("https://crt.sh/?q="+encodeURIComponent("%25."+domain)+"&output=json");if(!r.ok)throw Error("crt.sh indisponível: "+r.status);const data=await r.json();const names=[...new Set(data.flatMap(x=>String(x.name_value||"").split(/\r?\n/)).map(x=>x.trim().toLowerCase()).filter(x=>x===domain||x.endsWith("."+domain)))].sort();const result={domain,certificateEntries:data.length,subdomains:names,source:"crt.sh",note:"Certificado publicado não confirma que o subdomínio esteja ativo."};output("op-ct-result",result);await save("certificate-transparency","Certificados: "+domain,result);});
 bind("op-url-run",async()=>{const raw=document.getElementById("op-url-value").value.trim();const u=new URL(raw);if(!["http:","https:"].includes(u.protocol))throw Error("Somente HTTP/HTTPS.");const keys=[...u.searchParams.keys()];const result={url:u.href,protocol:u.protocol,hostname:u.hostname,port:u.port||"padrão",path:u.pathname,parameterNames:keys,possibleRedirectParameters:keys.filter(k=>/^(url|uri|redirect|redirect_uri|next|return|continue|dest|target)$/i.test(k)),credentialsInUrl:Boolean(u.username||u.password),note:"Inspeção estática; nenhum site foi acessado."};output("op-url-result",result);await save("url-inspection","Inspeção: "+u.hostname,result);});
 bind("op-tls-run",async()=>{const raw=document.getElementById("op-tls-domain").value.trim();const u=new URL(/^https?:\/\//i.test(raw)?raw:"https://"+raw);if(u.protocol!=="https:")throw Error("O endereço não usa HTTPS.");output("op-tls-result","O navegador está tentando estabelecer conexão HTTPS...");const started=performance.now();await fetch(u.origin,{mode:"no-cors",cache:"no-store",signal:AbortSignal.timeout(10000)});const result={origin:u.origin,connectionAttempted:true,elapsedMs:Math.round(performance.now()-started),note:"Conexão opaca: não valida cadeia, hostname, validade ou configuração completa do certificado TLS."};output("op-tls-result",result);await save("https-check","HTTPS: "+u.hostname,result);});
 document.getElementById("op-load-reports")?.addEventListener("click",async()=>{const root=document.getElementById("op-reports-list");root.textContent="Carregando...";try{const data=await api("/api/reports");root.replaceChildren();(data.reports||[]).forEach(item=>{const a=document.createElement("article");const b=document.createElement("b");b.textContent=item.title;const p=document.createElement("p");p.textContent=new Date(item.created_at).toLocaleString("pt-BR")+" · "+item.kind;a.append(b,p);root.append(a);});if(!root.children.length)root.textContent="Nenhum relatório salvo.";}catch(e){root.textContent="Erro: "+e.message;}});
}
initReconTools();