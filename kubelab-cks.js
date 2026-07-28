/* ==========================================================================
 * kubelab-cks.js — CKS Security learning modules for KubeLab.
 *
 * Plugs into the KubeLab app shell (see kubelab.html -> window.KL). Adds a
 * "CKS Security" sidebar group with interactive, browser-only simulators that
 * teach the Certified Kubernetes Security Specialist (CKS) domains:
 *   Cluster Setup · Cluster Hardening · System Hardening ·
 *   Minimize Microservice Vulnerabilities · Supply Chain Security ·
 *   Monitoring, Logging & Runtime Security
 *
 * Content is grounded in the Wiz "Kubernetes Security" and "Container
 * Security" best-practices cheat sheets (etcd/kubelet/apiserver hardening,
 * NetworkPolicy default-deny, Pod Security Standards, KMS/secret managers,
 * Cosign/SBOM/SLSA supply chain, Falco/Tetragon runtime detection).
 * Everything runs 100% client-side — no cluster, no network.
 * ======================================================================== */
(function () {
  "use strict";
  if (!window.KL) { console.error("KubeLab shell (window.KL) not found"); return; }
  const { $, $$, sleep, esc, APP } = window.KL;

  // ---- extra state on the shared pod spec (used by the PSS lab) -----------
  Object.assign(APP.podSpec, {
    hostPID: APP.podSpec.hostPID ?? false,
    hostPath: APP.podSpec.hostPath ?? false,
    readOnlyRootFilesystem: APP.podSpec.readOnlyRootFilesystem ?? false,
    dropAllCaps: APP.podSpec.dropAllCaps ?? false,
    seccomp: APP.podSpec.seccomp ?? "Unconfined",
  });

  // ---- module-specific CSS -------------------------------------------------
  KL.injectCSS(`
    .cks-domain{ border:1px solid var(--border); border-radius:12px; margin-bottom:12px; background:var(--panel); overflow:hidden; }
    .cks-domain .dh{ display:flex; align-items:center; gap:10px; padding:12px 15px; cursor:pointer; background:var(--panel-2); }
    .cks-domain .dh .w{ margin-left:auto; font-family:var(--mono); color:var(--k8s-blue); font-weight:700; }
    .cks-domain .db{ padding:12px 15px; display:none; }
    .cks-domain.open .db{ display:block; }
    .cks-domain ul{ margin:0 0 10px; padding-left:18px; line-height:1.6; color:#cdd8e3; font-size:13px; }
    .bar{ height:6px; border-radius:999px; background:var(--panel-3); overflow:hidden; flex:0 0 90px; }
    .bar i{ display:block; height:100%; background:linear-gradient(90deg,var(--k8s-blue),#6ea8ff); }
    .chk{ display:flex; gap:10px; align-items:flex-start; padding:9px 10px; border:1px solid var(--border); border-radius:8px; margin-bottom:7px; }
    .chk .ico{ flex:0 0 auto; font-size:14px; }
    .toggle-row{ display:flex; justify-content:space-between; align-items:center; padding:7px 0; border-bottom:1px solid var(--border); }
    .toggle-row small{ color:var(--muted); display:block; font-size:11px; }
    /* netpol graph */
    #np-graph{ position:relative; display:flex; justify-content:space-between; gap:10px; padding:24px 10px; min-height:120px; }
    .np-pod{ flex:1; border:1px solid var(--border); border-radius:10px; padding:12px 8px; text-align:center; background:var(--panel-2); font-size:12px; position:relative; z-index:2; }
    .np-pod .lbl{ font-family:var(--mono); font-size:10px; color:var(--muted); margin-top:3px; }
    #np-token{ position:absolute; top:44px; left:0; width:22px; height:22px; border-radius:6px; background:linear-gradient(135deg,var(--k8s-blue),#6ea8ff); display:flex; align-items:center; justify-content:center; font-size:12px; opacity:0; transition:transform .9s cubic-bezier(.5,.05,.3,1); z-index:3; }
    .np-matrix td, .np-matrix th{ text-align:center; cursor:pointer; }
    .np-matrix td:hover{ background:var(--panel-3); }
    /* runtime feed */
    .feed{ max-height:340px; overflow-y:auto; }
    .alert{ border-left:4px solid var(--border); background:var(--panel-2); border-radius:0 8px 8px 0; padding:9px 12px; margin-bottom:8px; animation:fade .25s ease; }
    .alert.Critical{ border-color:var(--red);} .alert.Warning{ border-color:var(--amber);} .alert.Notice{ border-color:var(--cyan);} .alert.Blocked{ border-color:var(--purple);}
    .alert .at{ display:flex; gap:8px; align-items:center; font-size:12.5px; font-weight:600; }
    .alert .ad{ color:var(--muted); font-size:11.5px; margin-top:3px; font-family:var(--mono); }
    .mitre{ font-size:10px; border:1px solid var(--border); border-radius:6px; padding:1px 6px; color:var(--muted); margin-left:auto; }
    .approach{ border:1px solid var(--border); border-radius:8px; padding:10px 12px; margin-bottom:8px; }
    .approach h4{ margin:0 0 4px; font-size:13px; } .approach p{ margin:0; color:var(--muted); font-size:12px; line-height:1.5; }
  `);

  /* =======================================================================
   * 1. CKS DOMAINS OVERVIEW
   * ===================================================================== */
  const DOMAINS = [
    { name: "Cluster Setup", w: 15, items: [
        "Use NetworkPolicies to restrict cluster-level access (start default-deny)",
        "Use the CIS benchmark to review security config of etcd, kubelet, kube-dns, kube-apiserver",
        "Properly set up Ingress with TLS",
        "Protect node metadata and endpoints",
        "Verify platform binaries before deploying"], labs: [["netpol","NetworkPolicy Visualizer"],["cluster-hardening","CIS Auditor"]] },
    { name: "Cluster Hardening", w: 15, items: [
        "Use RBAC to minimize exposure",
        "Exercise caution with ServiceAccounts (disable defaults, minimize permissions)",
        "Restrict access to the Kubernetes API (anonymous-auth, authz mode)",
        "Upgrade Kubernetes to avoid vulnerabilities"], labs: [["cluster-hardening","CIS Auditor"],["rbac","RBAC Lab"]] },
    { name: "System Hardening", w: 10, items: [
        "Minimize host OS footprint (reduce attack surface)",
        "Use least-privilege identity and access management",
        "Minimize external access to the network",
        "Use kernel hardening tools such as AppArmor and seccomp"], labs: [["pss","Pod Security Standards"],["runtime","Runtime Security"]] },
    { name: "Minimize Microservice Vulnerabilities", w: 20, items: [
        "Use appropriate Pod Security Standards (baseline / restricted)",
        "Manage Kubernetes secrets (encryption at rest, external managers)",
        "Use isolation techniques (multi-tenancy, sandboxed runtimes gVisor/Kata)",
        "Implement pod-to-pod encryption (Cilium/Istio mTLS)"], labs: [["pss","Pod Security Standards"],["secrets","Secrets & Encryption"],["netpol","NetworkPolicy Visualizer"]] },
    { name: "Supply Chain Security", w: 20, items: [
        "Minimize base image footprint (distroless)",
        "Understand your supply chain (SBOM, CI/CD, artifact repos)",
        "Secure your supply chain (permitted registries, sign & verify with Cosign)",
        "Static analysis of workloads and images (Kubesec, KubeLinter, Trivy)"], labs: [["supplychain","Supply Chain Lab"]] },
    { name: "Monitoring, Logging & Runtime Security", w: 20, items: [
        "Behavioral analytics to detect malicious activity (Falco, Tetragon)",
        "Detect threats across infra, apps, networks, data, users, workloads",
        "Investigate & identify phases of an attack (MITRE ATT&CK)",
        "Ensure immutability of containers at runtime",
        "Use Kubernetes audit logs to monitor access"], labs: [["runtime","Runtime Security"]] },
  ];
  function renderCksOverview() {
    $("#view-cks-overview").innerHTML = `
      <h2 class="title">CKS Security Domains</h2>
      <p class="subtitle">Interactive labs mapped to the six <b>Certified Kubernetes Security Specialist</b> domains, grounded in the Kubernetes &amp; Container security best-practice cheat sheets. Click a domain to expand its competencies and jump to a hands-on lab.</p>
      <div id="cks-domlist">
      ${DOMAINS.map((d,i)=>`
        <div class="cks-domain" data-i="${i}">
          <div class="dh"><b>${d.name}</b><div class="bar" title="exam weight"><i style="width:${d.w*4}%"></i></div><span class="w">${d.w}%</span><span style="color:var(--muted)">▸</span></div>
          <div class="db">
            <ul>${d.items.map(x=>`<li>${x}</li>`).join("")}</ul>
            <div class="row">${d.labs.map(l=>`<button class="btn sm" data-goto="${l[0]}">→ ${l[1]}</button>`).join("")}</div>
          </div>
        </div>`).join("")}
      </div>
      <div class="expl" style="margin-top:16px"><b>How to use this:</b> each lab <i>simulates</i> the concept so you can build intuition — audit a cluster, watch a packet get dropped by a NetworkPolicy, classify a Pod against Pod Security Standards, gate an image at admission, decode a Secret, and trigger runtime alerts. Great for CKS prep and interviews.</div>`;
    $$("#view-cks-overview .dh").forEach(h => h.onclick = () => h.parentElement.classList.toggle("open"));
    $$("#view-cks-overview [data-goto]").forEach(b => b.onclick = (e) => { e.stopPropagation(); KL.navigate(b.dataset.goto); });
  }

  /* =======================================================================
   * 2. CLUSTER HARDENING — CIS / kube-bench auditor
   * ===================================================================== */
  const cis = {
    kubeletAnonAuth: true, kubeletAuthzAlwaysAllow: true, kubeletReadOnlyPort: true, nodeRestriction: false,
    apiAnonAuth: true, rbacEnabled: false, auditLog: false,
    etcdClientCertAuth: false, etcdPeerTLS: false, secretsEncryption: false, thirdPartyAuth: false,
  };
  const CIS_CHECKS = [
    { g:"kubelet", k:"kubeletAnonAuth", secure:v=>!v, title:"Kubelet anonymous auth disabled", sev:"high",
      rem:"Set --anonymous-auth=false on the kubelet so unauthenticated callers can't hit its API." },
    { g:"kubelet", k:"kubeletAuthzAlwaysAllow", secure:v=>!v, title:"Kubelet authorization mode is not AlwaysAllow", sev:"high",
      rem:"Never run --authorization-mode=AlwaysAllow; use Webhook so the apiserver authorizes kubelet requests." },
    { g:"kubelet", k:"kubeletReadOnlyPort", secure:v=>!v, title:"Kubelet read-only port shut down", sev:"medium",
      rem:"Set --read-only-port=0 to close the unauthenticated 10255 metrics/spec port." },
    { g:"kubelet", k:"nodeRestriction", secure:v=>v, title:"NodeRestriction admission plugin enabled", sev:"high",
      rem:"Enable the NodeRestriction admission controller so a kubelet can only modify its own node/pods." },
    { g:"apiserver", k:"apiAnonAuth", secure:v=>!v, title:"API server anonymous auth disabled", sev:"critical",
      rem:"Set --anonymous-auth=false on kube-apiserver; anonymous access to the API is a disaster." },
    { g:"apiserver", k:"rbacEnabled", secure:v=>v, title:"RBAC authorization enabled", sev:"critical",
      rem:"Use --authorization-mode=Node,RBAC. Never rely on ABAC/AlwaysAllow." },
    { g:"apiserver", k:"auditLog", secure:v=>v, title:"Audit logging enabled", sev:"medium",
      rem:"Configure --audit-policy-file/--audit-log-path to keep track of every action in the cluster." },
    { g:"apiserver", k:"thirdPartyAuth", secure:v=>v, title:"Structured/OIDC authentication configured", sev:"low",
      rem:"Use --authentication-config (OIDC via Dex/Entra/IAM) instead of sharing kubeconfig files." },
    { g:"etcd", k:"etcdClientCertAuth", secure:v=>v, title:"etcd client-to-server TLS + client cert auth", sev:"critical",
      rem:"Set --cert-file/--key-file/--client-cert-auth/--trusted-ca-file so only trusted clients reach etcd." },
    { g:"etcd", k:"etcdPeerTLS", secure:v=>v, title:"etcd peer (server-to-server) TLS", sev:"high",
      rem:"Set --peer-cert-file/--peer-key-file/--peer-client-cert-auth for peer connections." },
    { g:"etcd", k:"secretsEncryption", secure:v=>v, title:"Secrets encrypted at rest (KMS v2)", sev:"critical",
      rem:"etcd stores Secrets base64-encoded, NOT encrypted. Enable --encryption-provider-config with a KMS v2 provider." },
  ];
  function renderClusterHardening() {
    const groups = { apiserver:"kube-apiserver", kubelet:"kubelet", etcd:"etcd" };
    const flag = (c) => {
      const val = cis[c.k]; const isBool = true;
      const label = ({kubeletAnonAuth:"--anonymous-auth (kubelet)",kubeletAuthzAlwaysAllow:"--authorization-mode=AlwaysAllow",kubeletReadOnlyPort:"--read-only-port (open)",nodeRestriction:"NodeRestriction admission",apiAnonAuth:"--anonymous-auth (apiserver)",rbacEnabled:"--authorization-mode includes RBAC",auditLog:"audit logging",thirdPartyAuth:"structured/OIDC auth",etcdClientCertAuth:"etcd client TLS + cert auth",etcdPeerTLS:"etcd peer TLS",secretsEncryption:"encryption-provider-config (KMS)"})[c.k];
      return `<div class="toggle-row"><div><code>${label}</code><small>${c.title}</small></div><label class="switch"><input type="checkbox" data-cis="${c.k}" ${val?"checked":""}></label></div>`;
    };
    $("#view-cluster-hardening").innerHTML = `
      <h2 class="title">Cluster Hardening — CIS Benchmark Auditor</h2>
      <p class="subtitle">Toggle control-plane and node flags to model a cluster's configuration, then run a <b>kube-bench</b>-style audit. Findings and remediation come straight from the CIS Kubernetes benchmark and the security cheat sheet.</p>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Cluster configuration</div><div class="pb">
          ${Object.entries(groups).map(([g,label])=>`<label class="fld" style="text-transform:uppercase">${label}</label>${CIS_CHECKS.filter(c=>c.g===g).map(flag).join("")}`).join("")}
          <div class="row" style="margin-top:14px"><button class="btn" id="cis-run">▶ Run kube-bench audit</button><button class="btn ghost" id="cis-harden">🔒 Harden all</button></div>
        </div></div>
        <div class="panel"><div class="ph">Audit report <span id="cis-score-pill"></span></div><div class="pb">
          <div style="text-align:center;margin-bottom:12px"><div class="score" id="cis-score">—</div><div class="hint">CIS pass rate</div></div>
          <div class="findings" id="cis-findings"><p class="hint">Toggle flags and run the audit. Note how many controls default to insecure — a fresh cluster is <b>not</b> hardened out of the box.</p></div>
        </div></div>
      </div>`;
    $$("#view-cluster-hardening [data-cis]").forEach(c => c.onchange = () => { cis[c.dataset.cis] = c.checked; });
    $("#cis-harden").onclick = () => {
      cis.kubeletAnonAuth=false; cis.kubeletAuthzAlwaysAllow=false; cis.kubeletReadOnlyPort=false; cis.nodeRestriction=true;
      cis.apiAnonAuth=false; cis.rbacEnabled=true; cis.auditLog=true; cis.thirdPartyAuth=true;
      cis.etcdClientCertAuth=true; cis.etcdPeerTLS=true; cis.secretsEncryption=true;
      renderClusterHardening(); runCisAudit();
    };
    $("#cis-run").onclick = runCisAudit;
  }
  function runCisAudit() {
    const results = CIS_CHECKS.map(c => ({ ...c, ok: c.secure(cis[c.k]) }));
    const pass = results.filter(r => r.ok).length;
    const pct = Math.round(pass / results.length * 100);
    $("#cis-score").textContent = pct + "%";
    $("#cis-score").style.color = pct>=90?"var(--green)":pct>=60?"var(--amber)":"var(--red)";
    $("#cis-score-pill").innerHTML = `<span class="pill ${pct>=90?'ok':pct>=60?'warn':'no'}">${pass}/${results.length} passed</span>`;
    results.sort((a,b)=> (a.ok-b.ok) || 0);
    $("#cis-findings").innerHTML = results.map(r => `<div class="f"><span class="sev ${r.ok?'pass':r.sev}">${r.ok?'PASS':r.sev.toUpperCase()}</span><div><b>${r.title}</b>${r.ok?'':`<div class="hint" style="margin-top:3px">${r.rem}</div>`}</div></div>`).join("");
  }

  /* =======================================================================
   * 3. NETWORKPOLICY VISUALIZER
   * ===================================================================== */
  const NP_PODS = [
    { id:"internet", name:"Internet", lbl:"external", icon:"🌐" },
    { id:"frontend", name:"frontend", lbl:"app=frontend", icon:"🖥️" },
    { id:"backend",  name:"backend",  lbl:"app=backend",  icon:"⚙️" },
    { id:"db",       name:"database",  lbl:"app=db",       icon:"🗄️" },
    { id:"metrics",  name:"monitoring",lbl:"app=metrics",  icon:"📈" },
  ];
  const np = { defaultDeny: true, rules: [ { from:"internet", to:"frontend", port:443 }, { from:"frontend", to:"backend", port:8080 }, { from:"backend", to:"db", port:5432 } ] };
  function npAllowed(from, to) {
    if (from === to) return { ok:true, why:"same pod" };
    if (!np.defaultDeny) return { ok:true, why:"no default-deny in this namespace — all traffic is allowed (the insecure default)" };
    const r = np.rules.find(x => x.from===from && x.to===to);
    if (r) return { ok:true, why:`allowed by NetworkPolicy rule: from <code>${from}</code> → <code>${to}</code> on port ${r.port}` };
    return { ok:false, why:`no allow rule matches <code>${from}</code> → <code>${to}</code>, and the namespace is <b>default-deny</b> (ingress+egress). Packet dropped.` };
  }
  function renderNetpol() {
    $("#view-netpol").innerHTML = `
      <h2 class="title">NetworkPolicy Visualizer</h2>
      <p class="subtitle">By default every pod can talk to every other pod. Best practice: start each namespace with a <b>default-deny</b> for ingress <i>and</i> egress, then add explicit allow rules (Calico/Cilium). Click any cell in the matrix to send a test packet and watch it get allowed or dropped.</p>
      <div class="panel" style="margin-bottom:16px"><div class="pb">
        <div class="row" style="justify-content:space-between">
          <label class="switch"><input type="checkbox" id="np-dd" ${np.defaultDeny?"checked":""}> namespace <code>default-deny-all</code> (Ingress + Egress)</label>
          <span class="hint">Toggle off to see the insecure "allow all" default.</span>
        </div>
        <div id="np-graph"><div id="np-token">📦</div>${NP_PODS.map(p=>`<div class="np-pod" id="np-${p.id}"><div style="font-size:20px">${p.icon}</div>${p.name}<div class="lbl">${p.lbl}</div></div>`).join("")}</div>
      </div></div>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Connectivity matrix <span class="hint">(click a cell: row → column)</span></div><div class="pb" style="overflow-x:auto">
          <table class="np-matrix"><tr><th>from ↓ / to →</th>${NP_PODS.map(p=>`<th>${p.name}</th>`).join("")}</tr>
          ${NP_PODS.map(f=>`<tr><th>${f.name}</th>${NP_PODS.map(t=>{ if(f.id===t.id) return `<td style="color:var(--muted)">—</td>`; const a=npAllowed(f.id,t.id); return `<td data-from="${f.id}" data-to="${t.id}"><span class="pill ${a.ok?'ok':'no'}">${a.ok?'✓':'✗'}</span></td>`; }).join("")}</tr>`).join("")}
          </table>
        </div></div>
        <div class="panel"><div class="ph">Test result &amp; rules</div><div class="pb">
          <div id="np-result" class="expl">Click a matrix cell to trace a connection.</div>
          <label class="fld">Allow rules <span class="badge-count">${np.rules.length}</span></label>
          <div id="np-rules">${npRulesHtml()}</div>
          <label class="fld">Add allow rule</label>
          <div class="row">
            <select id="np-from" style="flex:1">${NP_PODS.map(p=>`<option value="${p.id}">${p.name}</option>`).join("")}</select><span>→</span>
            <select id="np-to" style="flex:1">${NP_PODS.map(p=>`<option value="${p.id}">${p.name}</option>`).join("")}</select>
            <input type="number" id="np-port" value="80" style="width:80px">
            <button class="btn sm" id="np-add">Allow</button>
          </div>
        </div></div>
      </div>`;
    $("#np-dd").onchange = e => { np.defaultDeny = e.target.checked; renderNetpol(); };
    $$("#view-netpol .np-matrix td[data-from]").forEach(td => td.onclick = () => npTest(td.dataset.from, td.dataset.to));
    $("#np-add").onclick = () => { const f=$("#np-from").value,t=$("#np-to").value,p=parseInt($("#np-port").value||"80",10); if(f!==t&&!np.rules.find(r=>r.from===f&&r.to===t)) np.rules.push({from:f,to:t,port:p}); renderNetpol(); };
    $$("#view-netpol [data-delrule]").forEach(b => b.onclick = () => { np.rules.splice(+b.dataset.delrule,1); renderNetpol(); });
  }
  function npRulesHtml() {
    if (!np.rules.length) return `<p class="hint">no rules — with default-deny on, nothing can talk.</p>`;
    return np.rules.map((r,i)=>`<div class="chk"><span class="ico">✓</span><div style="flex:1"><code>${r.from} → ${r.to} : ${r.port}</code></div><button class="btn sm ghost" data-delrule="${i}">✕</button></div>`).join("");
  }
  async function npTest(from, to) {
    const a = npAllowed(from, to);
    const token = $("#np-token"), g = $("#np-graph"), src = $("#np-"+from), dst = $("#np-"+to);
    const gr = g.getBoundingClientRect();
    token.style.transition="none"; token.style.opacity="1";
    token.style.transform = `translateX(${src.getBoundingClientRect().left - gr.left + src.offsetWidth/2 - 11}px)`;
    await sleep(30); token.style.transition="transform .9s cubic-bezier(.5,.05,.3,1)";
    const midX = a.ok ? (dst.getBoundingClientRect().left - gr.left + dst.offsetWidth/2 - 11)
                      : ((src.getBoundingClientRect().left + dst.getBoundingClientRect().left)/2 - gr.left - 11);
    token.style.transform = `translateX(${midX}px)`;
    await sleep(950);
    if (!a.ok) { token.textContent="⛔"; }
    $("#np-result").innerHTML = `<div class="pill ${a.ok?'ok':'no'}" style="font-size:14px;padding:6px 12px">${a.ok?'ALLOWED':'DROPPED'}</div><p style="margin:8px 0 0">${NP_PODS.find(p=>p.id===from).name} → ${NP_PODS.find(p=>p.id===to).name}: ${a.why}</p>`;
    setTimeout(()=>{ token.textContent="📦"; token.style.opacity="0"; }, 1400);
  }

  /* =======================================================================
   * 4. POD SECURITY STANDARDS analyzer
   * ===================================================================== */
  function pssEval(p) {
    const baseline = [];
    if (p.privileged) baseline.push("privileged container");
    if (p.hostNetwork || p.hostPID) baseline.push("host namespaces (hostNetwork/hostPID)");
    if (p.hostPath) baseline.push("hostPath volume");
    const badCaps = (p.addedCaps||[]).filter(c => c !== "NET_BIND_SERVICE");
    if (badCaps.length) baseline.push("adds disallowed capabilities: " + badCaps.join(", "));
    if (p.seccomp === "Unconfined") baseline.push("seccompProfile is Unconfined");
    const restricted = baseline.slice();
    if (!p.runAsNonRoot) restricted.push("must set runAsNonRoot: true");
    if (p.allowPrivEsc) restricted.push("allowPrivilegeEscalation must be false");
    if (!p.dropAllCaps) restricted.push("must drop ALL capabilities");
    if (p.seccomp !== "RuntimeDefault" && p.seccomp !== "Localhost") restricted.push("seccompProfile must be RuntimeDefault or Localhost");
    const highest = restricted.length===0 ? "restricted" : baseline.length===0 ? "baseline" : "privileged";
    return { baseline, restricted, highest };
  }
  function renderPss() {
    const p = APP.podSpec;
    $("#view-pss").innerHTML = `
      <h2 class="title">Pod Security Standards</h2>
      <p class="subtitle">Pod Security Admission (PSA) replaced PodSecurityPolicy. It enforces three profiles at the <b>namespace</b> level via labels: <code>privileged</code> (unrestricted), <code>baseline</code> (blocks known escalations), and <code>restricted</code> (hardened, production best practice) — each in <code>enforce</code>, <code>warn</code>, or <code>audit</code> mode. Configure a pod and see which profile it satisfies.</p>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Pod securityContext <span class="hint">(shared with Container Security lab)</span></div><div class="pb">
          <div class="row"><label class="switch"><input type="checkbox" id="p-priv" ${p.privileged?'checked':''}> privileged</label>
            <label class="switch"><input type="checkbox" id="p-nonroot" ${p.runAsNonRoot?'checked':''}> runAsNonRoot</label>
            <label class="switch"><input type="checkbox" id="p-esc" ${p.allowPrivEsc?'checked':''}> allowPrivilegeEscalation</label></div>
          <div class="row" style="margin-top:8px"><label class="switch"><input type="checkbox" id="p-hnet" ${p.hostNetwork?'checked':''}> hostNetwork</label>
            <label class="switch"><input type="checkbox" id="p-hpid" ${p.hostPID?'checked':''}> hostPID</label>
            <label class="switch"><input type="checkbox" id="p-hpath" ${p.hostPath?'checked':''}> hostPath volume</label></div>
          <div class="row" style="margin-top:8px"><label class="switch"><input type="checkbox" id="p-dropall" ${p.dropAllCaps?'checked':''}> drop ALL capabilities</label>
            <label class="switch"><input type="checkbox" id="p-cap" ${(p.addedCaps||[]).includes('SYS_ADMIN')?'checked':''}> add CAP_SYS_ADMIN</label></div>
          <label class="fld">seccompProfile.type</label>
          <select id="p-seccomp"><option ${p.seccomp==='Unconfined'?'selected':''}>Unconfined</option><option ${p.seccomp==='RuntimeDefault'?'selected':''}>RuntimeDefault</option><option ${p.seccomp==='Localhost'?'selected':''}>Localhost</option></select>
          <label class="fld">Namespace enforce label</label>
          <select id="p-enforce"><option value="baseline">pod-security.kubernetes.io/enforce: baseline</option><option value="restricted" selected>pod-security.kubernetes.io/enforce: restricted</option></select>
          <button class="btn" id="p-eval" style="margin-top:14px">📛 Classify pod</button>
        </div></div>
        <div class="panel"><div class="ph">Result</div><div class="pb" id="pss-result"><p class="hint">Configure the pod and click “Classify pod”. Try the defaults (nginx runs as root, seccomp Unconfined) then harden it step by step to reach <code>restricted</code>.</p></div></div>
      </div>`;
    const sync = () => {
      p.privileged=$("#p-priv").checked; p.runAsNonRoot=$("#p-nonroot").checked; p.allowPrivEsc=$("#p-esc").checked;
      p.hostNetwork=$("#p-hnet").checked; p.hostPID=$("#p-hpid").checked; p.hostPath=$("#p-hpath").checked;
      p.dropAllCaps=$("#p-dropall").checked; p.addedCaps=$("#p-cap").checked?["SYS_ADMIN"]:[]; p.seccomp=$("#p-seccomp").value;
    };
    $$("#view-pss input, #view-pss select").forEach(i => i.addEventListener("change", sync));
    $("#p-eval").onclick = () => {
      sync(); const r = pssEval(p); const enforce = $("#p-enforce").value;
      const admitted = enforce==="baseline" ? r.baseline.length===0 : r.restricted.length===0;
      const badge = (name, viol) => `<div class="f"><span class="sev ${viol.length?'high':'pass'}">${viol.length?'FAIL':'PASS'}</span><div><b>${name}</b>${viol.length?`<div class="hint" style="margin-top:3px">${viol.map(v=>'• '+v).join("<br>")}</div>`:' — satisfied'}</div></div>`;
      $("#pss-result").innerHTML = `
        <div style="text-align:center;margin-bottom:12px"><div class="score" style="font-size:22px;color:${r.highest==='restricted'?'var(--green)':r.highest==='baseline'?'var(--amber)':'var(--red)'}">highest profile: ${r.highest}</div></div>
        <div class="findings">${badge("baseline", r.baseline)}${badge("restricted", r.restricted)}</div>
        <div class="expl" style="margin-top:12px">Namespace enforces <b>${enforce}</b> → this pod would be <b style="color:${admitted?'var(--green)':'var(--red)'}">${admitted?'ADMITTED':'REJECTED'}</b>${admitted?'':` (fix the violations above, or the pod is blocked at admission).`}</div>`;
    };
  }

  /* =======================================================================
   * 5. SUPPLY CHAIN SECURITY lab
   * ===================================================================== */
  const CVE_DB = {
    "distroless": [], "alpine:3.19": [ ["CVE-2023-5678","low","openssl"] ],
    "node:18": [ ["CVE-2024-2201","medium","glibc"], ["CVE-2023-44487","high","http2"], ["CVE-2024-0567","medium","gnutls"] ],
    "ubuntu:22.04": [ ["CVE-2024-1086","critical","kernel-headers"], ["CVE-2023-4911","high","glibc"], ["CVE-2024-0567","medium","gnutls"], ["CVE-2023-29491","medium","ncurses"] ],
  };
  const sc = { base:"node:18", pin:"tag", signed:false, sbom:false, registry:"gcr.io/myorg", slsa:0 };
  function renderSupplyChain() {
    $("#view-supplychain").innerHTML = `
      <h2 class="title">Supply Chain Security</h2>
      <p class="subtitle">Container security starts at build time. Minimize the base image, pin by <b>digest</b> (tags are mutable), scan for CVEs (Trivy), generate an <b>SBOM</b>, sign with <b>Cosign</b> (keyless), and enforce it all at admission with the Sigstore Policy Controller. Build a pipeline and gate it.</p>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Build pipeline</div><div class="pb">
          <label class="fld">Base image</label>
          <select id="sc-base">${Object.keys(CVE_DB).map(b=>`<option ${b===sc.base?'selected':''}>${b}</option>`).join("")}</select>
          <label class="fld">Image reference</label>
          <select id="sc-pin"><option value="tag" ${sc.pin==='tag'?'selected':''}>by tag (mutable) — myimage:1.0</option><option value="digest" ${sc.pin==='digest'?'selected':''}>by digest (immutable) — myimage@sha256:…</option></select>
          <label class="fld">Registry</label>
          <select id="sc-reg"><option ${sc.registry==='gcr.io/myorg'?'selected':''}>gcr.io/myorg</option><option ${sc.registry==='docker.io/random'?'selected':''}>docker.io/random</option></select>
          <div class="row" style="margin-top:12px">
            <label class="switch"><input type="checkbox" id="sc-sign" ${sc.signed?'checked':''}> cosign keyless sign</label>
            <label class="switch"><input type="checkbox" id="sc-sbom" ${sc.sbom?'checked':''}> generate SBOM (Syft)</label>
          </div>
          <label class="fld">SLSA build level</label>
          <select id="sc-slsa"><option value="0" ${sc.slsa==0?'selected':''}>L0 (no provenance)</option><option value="2" ${sc.slsa==2?'selected':''}>L2</option><option value="3" ${sc.slsa==3?'selected':''}>L3</option></select>
          <div class="row" style="margin-top:14px"><button class="btn" id="sc-run">▶ Build, scan &amp; admit</button><button class="btn ghost" id="sc-harden">🔒 Harden</button></div>
        </div></div>
        <div class="panel"><div class="ph">Trivy scan &amp; admission gate</div><div class="pb">
          <div class="pipeline" id="sc-pipe" style="padding:16px 4px">${["Build","SBOM","Sign","Scan","Admission"].map((s,i)=>`<div class="stage" id="sc-st-${i}"><div class="st-name">${s}</div>${i<4?'<div class="arrow">›</div>':''}</div>`).join("")}</div>
          <div id="sc-result"><p class="hint">Build a pipeline and gate it. Try <code>node:18</code> by tag, unsigned (denied) vs <code>distroless</code> by digest, signed (admitted).</p></div>
        </div></div>
      </div>`;
    const sync = () => { sc.base=$("#sc-base").value; sc.pin=$("#sc-pin").value; sc.registry=$("#sc-reg").value; sc.signed=$("#sc-sign").checked; sc.sbom=$("#sc-sbom").checked; sc.slsa=+$("#sc-slsa").value; };
    $$("#view-supplychain input, #view-supplychain select").forEach(i => i.addEventListener("change", sync));
    $("#sc-harden").onclick = () => { sc.base="distroless"; sc.pin="digest"; sc.registry="gcr.io/myorg"; sc.signed=true; sc.sbom=true; sc.slsa=3; renderSupplyChain(); runSupplyChain(); };
    $("#sc-run").onclick = () => { sync(); runSupplyChain(); };
  }
  async function runSupplyChain() {
    for (let i=0;i<5;i++){ const s=$("#sc-st-"+i); s.className="stage"; }
    const cves = CVE_DB[sc.base] || [];
    const crit = cves.filter(c=>c[1]==="critical"||c[1]==="high");
    const controls = [
      { name:"Image signed & verified (Cosign / Sigstore)", ok:sc.signed, rem:"Sign in CI with cosign keyless and verify at admission via the Sigstore Policy Controller." },
      { name:"Pinned by digest (not a mutable tag)", ok:sc.pin==="digest", rem:"Reference images by @sha256 digest; tags can be silently swapped." },
      { name:"From a permitted registry", ok:sc.registry==="gcr.io/myorg", rem:"Only allow trusted registries (OPA/VAP forbidden-registries policy)." },
      { name:"No critical/high CVEs (Trivy)", ok:crit.length===0, rem:`Minimize the base image (distroless) and patch. Found ${crit.length} critical/high CVE(s).` },
      { name:"SBOM attached", ok:sc.sbom, rem:"Generate an SBOM with Syft/Trivy and attach it for auditability." },
      { name:"SLSA build provenance ≥ L2", ok:sc.slsa>=2, rem:"Produce provenance from a trusted build platform (aim for SLSA L2+)." },
    ];
    const stageResult = [true, sc.sbom, sc.signed, crit.length===0, controls.every(c=>c.ok)];
    for (let i=0;i<5;i++){ const s=$("#sc-st-"+i); s.classList.add("active"); await sleep(500); s.classList.remove("active"); s.classList.add(stageResult[i]?"pass":"fail"); }
    const admit = controls.every(c=>c.ok);
    $("#sc-result").innerHTML =
      `<div class="pill ${admit?'ok':'no'}" style="font-size:14px;padding:8px 14px">${admit?'✓ image ADMITTED':'✗ admission DENIED'}</div>`
      + `<div class="findings" style="margin-top:12px">${controls.map(c=>`<div class="f"><span class="sev ${c.ok?'pass':'high'}">${c.ok?'PASS':'FAIL'}</span><div><b>${c.name}</b>${c.ok?'':`<div class="hint" style="margin-top:3px">${c.rem}</div>`}</div></div>`).join("")}</div>`
      + (cves.length?`<label class="fld">Trivy findings for <code>${sc.base}</code></label>${cves.map(c=>`<div class="chk"><span class="sev ${c[1]}">${c[1].toUpperCase()}</span><div><code>${c[0]}</code> <span class="hint">(${c[2]})</span></div></div>`).join("")}`:`<p class="hint" style="margin-top:10px">Trivy: no known vulnerabilities in <code>${sc.base}</code> 🎉</p>`);
  }

  /* =======================================================================
   * 6. SECRETS & ENCRYPTION lab
   * ===================================================================== */
  const secState = { plaintext:"S3cr3t-DB-p@ss", encrypted:false, rotationDays:90 };
  function b64(s){ try { return btoa(s); } catch(e){ return btoa(unescape(encodeURIComponent(s))); } }
  function renderSecrets() {
    $("#view-secrets").innerHTML = `
      <h2 class="title">Secrets &amp; Encryption</h2>
      <p class="subtitle">A common misconception: Kubernetes Secrets are <b>not</b> encrypted by default — they're only base64-encoded in etcd. Anyone who can read the object (or etcd) can read the value. Learn the difference and the layered fixes: encryption at rest (KMS), external managers, and short-lived rotation.</p>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Secret object &amp; how it's stored</div><div class="pb">
          <label class="fld">Secret value (data.password)</label>
          <input type="text" id="sec-val" value="${esc(secState.plaintext)}">
          <label class="fld">What the manifest shows (base64)</label>
          <textarea rows="3" readonly id="sec-b64"></textarea>
          <div class="row" style="margin-top:8px"><button class="btn ghost" id="sec-decode">🔓 Decode base64 (as any reader can)</button></div>
          <div id="sec-decoded"></div>
          <label class="switch" style="margin-top:14px"><input type="checkbox" id="sec-enc" ${secState.encrypted?'checked':''}> Enable etcd encryption at rest (KMS v2, --encryption-provider-config)</label>
          <label class="fld">As stored in etcd</label>
          <div class="log" id="sec-etcd" style="min-height:auto"></div>
        </div></div>
        <div class="panel"><div class="ph">Approaches (least → most secure)</div><div class="pb">
          <div class="approach"><h4>① Plain Secret (default) <span class="pill no">base64 only</span></h4><p>Stored base64-encoded in etcd. Not encrypted. Readable by anyone with get access or etcd access.</p></div>
          <div class="approach"><h4>② etcd encryption at rest (KMS v2) <span class="pill warn">encrypted in etcd</span></h4><p>Envelope encryption via AWS/GCP/Azure KMS or Vault. DEK caching + key rotation without apiserver restart. Still a Secret object in the API.</p></div>
          <div class="approach"><h4>③ External Secrets Operator <span class="pill info">synced from a manager</span></h4><p>Syncs from Vault / AWS/GCP/Azure secret managers into K8s Secrets automatically — single source of truth, rotation handled upstream.</p></div>
          <div class="approach"><h4>④ Secrets Store CSI Driver <span class="pill ok">never in etcd</span></h4><p>Mounts secrets straight into the pod as a volume — no Secret object persists in etcd at all. Preferred for the highest-security workloads.</p></div>
          <label class="fld">Short-lived secret rotation: every <b id="sec-rot-lbl">${secState.rotationDays}</b> days</label>
          <input type="range" id="sec-rot" min="1" max="180" value="${secState.rotationDays}" style="width:100%">
          <div id="sec-rot-note" class="expl" style="margin-top:8px"></div>
        </div></div>
      </div>`;
    const refresh = () => {
      secState.plaintext = $("#sec-val").value;
      $("#sec-b64").value = `apiVersion: v1\nkind: Secret\ndata:\n  password: ${b64(secState.plaintext)}`;
      $("#sec-etcd").innerHTML = secState.encrypted
        ? `<span class="ok">k8s:enc:kms:v2:my-kms-key:` + b64(secState.plaintext).split("").reverse().join("").slice(0,24) + `…</span>  <span class="muted">(ciphertext — unreadable without the KMS key)</span>`
        : `<span class="warn">password: ${b64(secState.plaintext)}</span>  <span class="muted">(base64 — trivially decoded, NOT encrypted)</span>`;
    };
    $("#sec-val").oninput = refresh;
    $("#sec-enc").onchange = e => { secState.encrypted = e.target.checked; refresh(); };
    $("#sec-decode").onclick = () => { $("#sec-decoded").innerHTML = `<div class="expl" style="margin-top:10px">🔓 <code>echo '${b64(secState.plaintext)}' | base64 -d</code> → <b style="color:var(--red)">${esc(secState.plaintext)}</b><div class="hint" style="margin-top:4px">Base64 is encoding, not encryption. This is why you need encryption at rest and/or an external secret manager.</div></div>`; };
    const rotNote = () => {
      const d = secState.rotationDays;
      $("#sec-rot-lbl").textContent = d;
      const risk = d<=7?"tiny":d<=30?"small":d<=90?"moderate":"large";
      const color = d<=30?"var(--green)":d<=90?"var(--amber)":"var(--red)";
      $("#sec-rot-note").innerHTML = `Exposure window if a secret leaks: <b style="color:${color}">${risk}</b>. The cheat sheet recommends rotating every 30–90 days (or use dynamic, short-lived secrets from Vault). Shorter = smaller blast radius.`;
    };
    $("#sec-rot").oninput = e => { secState.rotationDays = +e.target.value; rotNote(); };
    refresh(); rotNote();
  }

  /* =======================================================================
   * 7. RUNTIME SECURITY — Falco / Tetragon
   * ===================================================================== */
  const RT_EVENTS = [
    { id:"shell", label:"Exec a shell in the container", rule:"Terminal shell in container", pri:"Warning", mitre:"T1059 Command & Scripting", detail:"a shell (/bin/bash) was spawned inside container payments-api", blockable:true },
    { id:"etcpw", label:"Write to /etc/passwd", rule:"Write below /etc", pri:"Critical", mitre:"T1098 Account Manipulation", detail:"fd_install on /etc/passwd (Tetragon kprobe) — file modified", blockable:true, needsImmutable:true },
    { id:"secret", label:"Read the mounted ServiceAccount token", rule:"Read sensitive file (SA token)", pri:"Warning", mitre:"T1552 Unsecured Credentials", detail:"read /var/run/secrets/kubernetes.io/serviceaccount/token", blockable:false },
    { id:"c2", label:"Outbound connection to 185.220.101.4 (C2)", rule:"Unexpected outbound connection", pri:"Critical", mitre:"T1071 C2 over Web", detail:"tcpConnect to 185.220.101.4:443 (not in egress allow-list)", blockable:true },
    { id:"pkg", label:"Run apk/apt inside the container", rule:"Launch package management in container", pri:"Notice", mitre:"T1072 Software Deployment", detail:"exec apk add curl — package manager should not run at runtime", blockable:true },
    { id:"escape", label:"Attempt container escape (mount host fs)", rule:"Container escape via privileged mount", pri:"Critical", mitre:"T1611 Escape to Host", detail:"mount /host && chroot — privileged container breakout attempt", blockable:true },
  ];
  const rt = { enforce:false, immutable:false, alerts:[] };
  function renderRuntime() {
    $("#view-runtime").innerHTML = `
      <h2 class="title">Runtime Security — Falco &amp; Tetragon</h2>
      <p class="subtitle">Image scanning can't catch threats that emerge at runtime. eBPF tools like <b>Falco</b> and <b>Tetragon</b> watch syscalls, files, processes and network activity, map events to <b>MITRE ATT&amp;CK</b>, and (with Tetragon/Talon) can <b>block</b> — not just observe. Trigger actions on a running pod and watch the detections.</p>
      <div class="grid cols-2">
        <div class="panel"><div class="ph">Running workload: <code>payments-api</code></div><div class="pb">
          <div class="row" style="justify-content:space-between;margin-bottom:10px">
            <label class="switch"><input type="checkbox" id="rt-enforce" ${rt.enforce?'checked':''}> Tetragon enforcement (block, not just alert)</label>
            <label class="switch"><input type="checkbox" id="rt-immutable" ${rt.immutable?'checked':''}> readOnlyRootFilesystem (immutable)</label>
          </div>
          ${RT_EVENTS.map(e=>`<button class="btn ghost sm" data-ev="${e.id}" style="display:block;width:100%;text-align:left;margin-bottom:6px">▶ ${e.label}</button>`).join("")}
          <button class="btn ghost sm" id="rt-clear" style="margin-top:6px">clear alert feed</button>
        </div></div>
        <div class="panel"><div class="ph">Detections &amp; audit feed <span class="badge-count" id="rt-count">0</span></div><div class="pb">
          <div class="feed" id="rt-feed"><p class="hint">Trigger an action on the left. Alerts map to MITRE ATT&CK. Turn on enforcement/immutability to see actions get blocked instead of just logged.</p></div>
        </div></div>
      </div>`;
    $("#rt-enforce").onchange = e => rt.enforce = e.target.checked;
    $("#rt-immutable").onchange = e => rt.immutable = e.target.checked;
    $("#rt-clear").onclick = () => { rt.alerts = []; renderRtFeed(); };
    $$("#view-runtime [data-ev]").forEach(b => b.onclick = () => rtTrigger(b.dataset.ev));
    renderRtFeed();
  }
  function rtTrigger(id) {
    const e = RT_EVENTS.find(x => x.id === id);
    const blocked = (rt.enforce && e.blockable) || (e.needsImmutable && rt.immutable);
    rt.alerts.unshift({
      pri: blocked ? "Blocked" : e.pri, rule: e.rule, mitre: e.mitre,
      detail: e.detail, blocked, when: new Date().toLocaleTimeString(),
      by: blocked ? (e.needsImmutable && rt.immutable && !rt.enforce ? "readOnlyRootFilesystem" : "Tetragon enforcement") : "Falco (observe)",
    });
    if (rt.alerts.length > 40) rt.alerts.pop();
    renderRtFeed();
  }
  function renderRtFeed() {
    $("#rt-count").textContent = rt.alerts.length;
    const f = $("#rt-feed");
    if (!rt.alerts.length) { f.innerHTML = `<p class="hint">No alerts yet. Trigger an action on the left.</p>`; return; }
    f.innerHTML = rt.alerts.map(a => `
      <div class="alert ${a.pri}">
        <div class="at"><span>${a.blocked?'⛔':'🚨'} ${a.rule}</span><span class="mitre">${a.mitre}</span></div>
        <div class="ad">${a.when} · priority=${a.pri} · ${a.blocked?`<b style="color:var(--purple)">BLOCKED by ${a.by}</b>`:`detected by ${a.by}`}<br>${esc(a.detail)}</div>
      </div>`).join("");
  }

  /* =======================================================================
   * REGISTER everything with the app shell
   * ===================================================================== */
  KL.addNavGroup("CKS Security", [
    ["cks-overview", "🎯", "CKS Domains"],
    ["cluster-hardening", "🧱", "Cluster Hardening / CIS"],
    ["netpol", "🕸️", "NetworkPolicy Viz"],
    ["pss", "📛", "Pod Security Standards"],
    ["supplychain", "📦", "Supply Chain"],
    ["secrets", "🔑", "Secrets & Encryption"],
    ["runtime", "🛰️", "Runtime Security"],
  ]);
  KL.addView("cks-overview", renderCksOverview);
  KL.addView("cluster-hardening", renderClusterHardening);
  KL.addView("netpol", renderNetpol);
  KL.addView("pss", renderPss);
  KL.addView("supplychain", renderSupplyChain);
  KL.addView("secrets", renderSecrets);
  KL.addView("runtime", renderRuntime);
})();
