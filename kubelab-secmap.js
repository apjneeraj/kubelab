/* ==========================================================================
 * kubelab-secmap.js — Kubernetes Security Topics Catalog + AuthN deep dive.
 *
 * Plugs into the KubeLab app shell (window.KL). Adds:
 *   1. Security Map — all 12 Kubernetes security domains (CKS, NSA/CISA,
 *      CIS, 4Cs) with status badges and jumps into existing labs.
 *   2. AuthN Deep Dive — interactive simulator for the authentication chain,
 *      legacy vs bound ServiceAccount tokens, automount, and Workload Identity.
 *
 * Everything runs 100% client-side — no cluster, no network.
 * ======================================================================== */
(function () {
  "use strict";
  if (!window.KL) { console.error("KubeLab shell (window.KL) not found"); return; }
  const { $, $$, sleep, esc } = window.KL;

  KL.injectCSS(`
    .fourcs{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:18px; }
    .fourcs .c{ border:1px solid var(--border); border-radius:10px; padding:12px; background:var(--panel-2); text-align:center; position:relative; }
    .fourcs .c .cn{ font-weight:700; font-size:13px; }
    .fourcs .c .cd{ color:var(--muted); font-size:11.5px; margin-top:4px; line-height:1.4; }
    .fourcs .c .arr{ position:absolute; right:-12px; top:50%; transform:translateY(-50%); color:var(--k8s-blue); font-size:18px; z-index:1; }
    @media (max-width:800px){ .fourcs{ grid-template-columns:1fr 1fr; } .fourcs .c .arr{ display:none; } }
    .map-filters{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; }
    .map-filters button{ background:var(--panel-3); color:var(--text); border:1px solid var(--border); border-radius:999px; padding:5px 12px; cursor:pointer; font-size:12px; font-family:var(--sans); }
    .map-filters button.on{ background:rgba(50,108,229,.25); border-color:var(--k8s-blue); }
    .topic{ border:1px solid var(--border); border-radius:12px; margin-bottom:10px; background:var(--panel); overflow:hidden; }
    .topic .th{ display:flex; align-items:center; gap:10px; padding:12px 15px; cursor:pointer; background:var(--panel-2); }
    .topic .th .num{ font-family:var(--mono); color:var(--k8s-blue); font-weight:700; width:22px; }
    .topic .tb{ padding:12px 15px 14px; display:none; }
    .topic.open .tb{ display:block; }
    .topic ul.titems{ margin:0 0 10px; padding-left:0; list-style:none; }
    .topic ul.titems li{ display:flex; gap:8px; align-items:flex-start; padding:5px 0; font-size:13px; line-height:1.45; color:#cdd8e3; border-bottom:1px solid var(--border); }
    .topic ul.titems li:last-child{ border-bottom:none; }
    .st{ font-size:10px; font-weight:700; padding:1px 7px; border-radius:6px; flex:0 0 auto; letter-spacing:.3px; text-transform:uppercase; }
    .st.lab{ background:rgba(63,185,80,.15); color:var(--green); }
    .st.partial{ background:rgba(210,153,34,.15); color:var(--amber); }
    .st.gap{ background:rgba(139,152,169,.15); color:var(--muted); }
    .st.deep{ background:rgba(50,108,229,.18); color:#8bb4ff; }
    .layer{ font-size:10px; color:var(--muted); border:1px solid var(--border); padding:1px 7px; border-radius:999px; }
    .legend{ display:flex; gap:10px; flex-wrap:wrap; margin:0 0 14px; font-size:12px; color:var(--muted); }
    .auth-stages{ display:flex; gap:8px; overflow-x:auto; padding:8px 2px 14px; }
    .auth-st{ flex:1 0 110px; min-width:110px; border:1px solid var(--border); border-radius:10px; background:var(--panel-2); padding:10px 8px; text-align:center; position:relative; transition:.2s; }
    .auth-st .nm{ font-size:12px; font-weight:600; }
    .auth-st .sub{ font-size:10.5px; color:var(--muted); margin-top:3px; min-height:28px; }
    .auth-st.active{ border-color:var(--k8s-blue); box-shadow:0 0 0 2px rgba(50,108,229,.35); }
    .auth-st.pass{ border-color:var(--green); background:rgba(63,185,80,.08); }
    .auth-st.skip{ opacity:.45; }
    .auth-st.match{ border-color:var(--cyan); background:rgba(86,212,221,.1); }
    .auth-st.fail{ border-color:var(--red); background:rgba(248,81,73,.1); }
    .jwt{ font-family:var(--mono); font-size:11.5px; background:#0a0e14; border:1px solid var(--border); border-radius:8px; padding:10px; white-space:pre-wrap; line-height:1.45; max-height:240px; overflow:auto; }
    .jwt .hdr{ color:#d29922; } .jwt .pl{ color:#56d4dd; } .jwt .sig{ color:var(--muted); }
    .idcard{ border:1px solid var(--border); border-radius:10px; padding:12px; background:var(--panel-2); }
    .idcard .who{ font-family:var(--mono); font-size:13px; color:var(--cyan); }
    .cmp{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    @media (max-width:800px){ .cmp{ grid-template-columns:1fr; } }
    .radio-list label{ display:flex; gap:8px; align-items:flex-start; padding:8px 10px; border:1px solid var(--border); border-radius:8px; margin-bottom:6px; cursor:pointer; background:var(--panel-2); font-size:13px; }
    .radio-list label:hover{ border-color:var(--k8s-blue); }
    .radio-list label.on{ border-color:var(--k8s-blue); background:rgba(50,108,229,.12); }
    .wi{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    @media (max-width:800px){ .wi{ grid-template-columns:1fr; } }
    .wi .box{ border:1px solid var(--border); border-radius:10px; padding:12px; }
    .wi .box.bad{ border-color:rgba(248,81,73,.45); }
    .wi .box.good{ border-color:rgba(63,185,80,.45); }
    .wi h4{ margin:0 0 6px; font-size:13px; }
    .wi p{ margin:0; color:var(--muted); font-size:12.5px; line-height:1.5; }
    .path{ font-family:var(--mono); font-size:11.5px; color:var(--muted); margin-top:8px; line-height:1.6; }
  `);

  /* =======================================================================
   * 1. SECURITY MAP — full Kubernetes security topic catalog
   * ===================================================================== */
  const CATALOG = [
    {
      n: 1, id: "authn", name: "Identity and authentication", layer: "Cluster",
      blurb: "Who is calling the API, and how is that proven?",
      items: [
        { t: "X.509 client certificates (kubeadm PKI, kubelet TLS bootstrap)", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "ServiceAccount tokens: legacy secret tokens vs bound / projected tokens (TokenRequest)", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "OIDC / structured authentication (AuthenticationConfiguration) — Dex, Entra, Google, GitHub", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Webhook token authentication", s: "gap" },
        { t: "Bootstrap tokens", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Impersonation (impersonate verb)", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Anonymous auth (--anonymous-auth)", s: "partial", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "kubeconfig hygiene (file perms, no shared admin configs, short-lived creds)", s: "gap" },
        { t: "Cloud Workload Identity (IRSA / GKE WI / Azure WI) instead of long-lived node IAM", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "MFA for humans; no shared cluster-admin kubeconfigs", s: "gap" },
      ],
    },
    {
      n: 2, id: "authz", name: "Authorization (RBAC and friends)", layer: "Cluster",
      blurb: "What is that identity allowed to do?",
      items: [
        { t: "RBAC: Role / ClusterRole / RoleBinding / ClusterRoleBinding", s: "lab", lab: ["rbac", "RBAC Lab"] },
        { t: "Dangerous verbs: escalate, bind, impersonate, *", s: "partial", lab: ["rbac", "RBAC Lab"] },
        { t: "Aggregation (aggregationRule) and default ClusterRoles (system:unauthenticated, system:authenticated)", s: "gap" },
        { t: "Node authorizer + NodeRestriction admission", s: "partial", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "ABAC (legacy — do not use)", s: "gap" },
        { t: "Webhook authorization", s: "gap" },
        { t: "kubectl auth can-i / SubjectAccessReview", s: "lab", lab: ["rbac", "RBAC Lab"] },
        { t: "Privilege via pods/exec, pods/attach, pods/portforward, nodes/proxy, secrets get, create pods", s: "partial", lab: ["rbac", "RBAC Lab"] },
        { t: "ServiceAccount least privilege; disable automount (automountServiceAccountToken: false)", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Disable default ServiceAccount in every namespace", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
      ],
    },
    {
      n: 3, id: "admission", name: "Admission control and policy-as-code", layer: "Cluster",
      blurb: "The last gate before etcd.",
      items: [
        { t: "Built-in plugins: NamespaceLifecycle, LimitRanger, ResourceQuota, ServiceAccount, NodeRestriction, AlwaysPullImages, EventRateLimit", s: "partial", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "Pod Security Admission (privileged / baseline / restricted × enforce / warn / audit)", s: "lab", lab: ["pss", "Pod Security Standards"] },
        { t: "Mutating vs validating webhooks", s: "partial", lab: ["opa", "OPA / Admission"] },
        { t: "ValidatingAdmissionPolicy (native CEL)", s: "gap" },
        { t: "OPA / Gatekeeper (ConstraintTemplate + Constraint)", s: "lab", lab: ["opa", "OPA / Admission"] },
        { t: "Kyverno (validate / mutate / generate / verifyImages)", s: "gap" },
        { t: "Kubewarden / jsPolicy", s: "gap" },
        { t: "ImagePolicyWebhook, Binary Authorization", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Defaulting vs rejecting; fail-open vs fail-closed webhooks", s: "gap" },
      ],
    },
    {
      n: 4, id: "cp", name: "Control plane / cluster hardening", layer: "Cluster",
      blurb: "Lock down apiserver, etcd, kubelet, scheduler, controller-manager.",
      items: [
        { t: "kube-apiserver: disable anonymous auth; --authorization-mode=Node,RBAC; audit policy; encryption-provider-config; API Priority and Fairness", s: "lab", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "etcd: mTLS client + peer; separate CA; no public etcd; encrypt at rest; backups encrypted", s: "lab", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "kubelet: --anonymous-auth=false; authz not AlwaysAllow; --read-only-port=0; rotate certs; ProtectKernelDefaults", s: "lab", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "CIS Kubernetes Benchmark (kube-bench)", s: "lab", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "Certificate rotation (apiserver, kubelet, etcd)", s: "gap" },
        { t: "Upgrade Kubernetes (CVE patch cadence)", s: "gap" },
        { t: "Verify platform binaries before install", s: "gap" },
        { t: "kubeadm / Cluster API / managed-control-plane differences (EKS/GKE/AKS shared responsibility)", s: "gap" },
      ],
    },
    {
      n: 5, id: "node", name: "Node and host (system) hardening", layer: "Cluster",
      blurb: "The node is part of the trusted computing base.",
      items: [
        { t: "Minimal OS (Flatcar, Bottlerocket, COS, Talos) — no SSH / no package manager", s: "gap" },
        { t: "CIS Linux / host benchmark", s: "gap" },
        { t: "Kernel hardening: sysctl, unprivileged user namespaces, kernel.kptr_restrict", s: "gap" },
        { t: "seccomp (RuntimeDefault / custom localhost profiles)", s: "partial", lab: ["pss", "Pod Security Standards"] },
        { t: "AppArmor / SELinux", s: "gap" },
        { t: "Linux capabilities (drop ALL, add back only what is needed)", s: "lab", lab: ["security", "Container Security"] },
        { t: "cgroups v2, PID / memory / CPU isolation as DoS defense", s: "partial", lab: ["security", "Container Security"] },
        { t: "No Docker socket mount; no privileged kubelet", s: "partial", lab: ["security", "Container Security"] },
        { t: "IMDS / cloud metadata protection (IMDSv2, hop limit, NetworkPolicy egress deny to 169.254.169.254)", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "eBPF: who can load programs", s: "gap" },
        { t: "Rootless / user-namespaced containers; gVisor / Kata / Firecracker sandboxes", s: "gap" },
        { t: "Confidential computing (TEEs)", s: "gap" },
      ],
    },
    {
      n: 6, id: "workload", name: "Workload / pod security", layer: "Container",
      blurb: "What a Pod is allowed to be.",
      items: [
        { t: "Pod securityContext / container securityContext", s: "lab", lab: ["security", "Container Security"] },
        { t: "runAsNonRoot, runAsUser, runAsGroup, fsGroup", s: "lab", lab: ["security", "Container Security"] },
        { t: "allowPrivilegeEscalation: false", s: "lab", lab: ["security", "Container Security"] },
        { t: "privileged: false; no hostPID / hostIPC / hostNetwork / hostPath", s: "lab", lab: ["pss", "Pod Security Standards"] },
        { t: "readOnlyRootFilesystem + explicit writable volumes", s: "partial", lab: ["runtime", "Runtime Security"] },
        { t: "seccompProfile, appArmorProfile, seLinuxOptions", s: "partial", lab: ["pss", "Pod Security Standards"] },
        { t: "Capabilities drop/add; forbidden SYS_ADMIN, NET_ADMIN, SYS_PTRACE", s: "lab", lab: ["security", "Container Security"] },
        { t: "procMount, sysctls (safe vs unsafe)", s: "gap" },
        { t: "Resource requests/limits (noisy-neighbor / fork-bomb)", s: "lab", lab: ["security", "Container Security"] },
        { t: "PriorityClass / DoS", s: "gap" },
        { t: "Sandboxed runtimes (runtimeClassName: gvisor / kata)", s: "gap" },
        { t: "Multi-tenancy: namespaces, ResourceQuota, LimitRange, HNC, vcluster", s: "gap" },
      ],
    },
    {
      n: 7, id: "net", name: "Network security and zero trust", layer: "Cluster",
      blurb: "Default Kubernetes networking is flat — every pod can reach every other pod.",
      items: [
        { t: "NetworkPolicy: default-deny ingress and egress; namespace isolation", s: "lab", lab: ["netpol", "NetworkPolicy Viz"] },
        { t: "CNI policy engines: Calico, Cilium (L3/L4/L7, FQDN, DNS)", s: "partial", lab: ["netpol", "NetworkPolicy Viz"] },
        { t: "Cilium ClusterwideNetworkPolicy; Hubble observability", s: "gap" },
        { t: "Ingress / Gateway API TLS; cert-manager", s: "gap" },
        { t: "Protect node metadata and cloud APIs from pods", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "kube-dns / CoreDNS hardening", s: "gap" },
        { t: "Pod-to-pod encryption: Cilium WireGuard/IPsec, Istio/Linkerd mTLS", s: "gap" },
        { t: "Service mesh AuthorizationPolicy", s: "gap" },
        { t: "Egress gateways; no wild-open NodePort / LoadBalancer", s: "gap" },
        { t: "Private API endpoint; authorized networks; no public kubelet", s: "gap" },
        { t: "HostNetwork / hostPort as escape hatches", s: "partial", lab: ["pss", "Pod Security Standards"] },
      ],
    },
    {
      n: 8, id: "secrets", name: "Secrets, data, and encryption", layer: "Cluster",
      blurb: "Secrets are base64, not encrypted, unless you turn encryption on.",
      items: [
        { t: "Secrets are base64, not encrypted, by default", s: "lab", lab: ["secrets", "Secrets & Encryption"] },
        { t: "EncryptionConfiguration / KMS v2 envelope encryption", s: "lab", lab: ["secrets", "Secrets & Encryption"] },
        { t: "Secret rotation; never bake secrets into images", s: "lab", lab: ["secrets", "Secrets & Encryption"] },
        { t: "External Secrets Operator (Vault, AWS/GCP/Azure SM)", s: "lab", lab: ["secrets", "Secrets & Encryption"] },
        { t: "Secrets Store CSI Driver (secret never persisted in etcd)", s: "lab", lab: ["secrets", "Secrets & Encryption"] },
        { t: "Sealed Secrets / SOPS for Git", s: "gap" },
        { t: "etcd snapshots contain secrets — encrypt backups", s: "gap" },
        { t: "Volume / PV encryption (CSI, cloud disk encryption)", s: "gap" },
        { t: "TLS everywhere: apiserver, etcd, kubelet, Ingress, mesh", s: "partial", lab: ["cluster-hardening", "CIS Auditor"] },
      ],
    },
    {
      n: 9, id: "supply", name: "Supply chain security", layer: "Code",
      blurb: "Build-time trust, not just runtime.",
      items: [
        { t: "Minimal / distroless / scratch base images", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Pin by digest, never mutable tags", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Permitted registries only", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Scan: Trivy, Grype, Clair; fail on critical/high", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "SBOM (Syft, SPDX, CycloneDX) + VEX", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Sign and verify: Cosign (keyless), Notation, Sigstore Policy Controller", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "SLSA provenance (L2+)", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Dockerfile / Helm / manifest static analysis (Kubesec, KubeLinter, Checkov)", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "CI OIDC federation (no long-lived cloud keys in pipelines)", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Chart provenance; disable Tiller-era patterns", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Admission: deny unsigned / unscanned / foreign-registry images", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Binary Authorization / in-toto", s: "partial", lab: ["supply-deep", "Supply Chain Deep Dive"] },
      ],
    },
    {
      n: 10, id: "runtime", name: "Runtime detection, audit, and response", layer: "Container",
      blurb: "What scanning cannot see.",
      items: [
        { t: "Kubernetes audit logs (stages: RequestReceived, ResponseComplete; omit secrets)", s: "partial", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "Falco rules; Tetragon / Tracee (eBPF enforce vs observe)", s: "lab", lab: ["runtime", "Runtime Security"] },
        { t: "MITRE ATT&CK for Containers (exec, credential access, C2, escape)", s: "lab", lab: ["runtime", "Runtime Security"] },
        { t: "Container immutability (readOnlyRootFilesystem; no apk/apt at runtime)", s: "lab", lab: ["runtime", "Runtime Security"] },
        { t: "Centralized logging (nodes, containers, audit, cloud) → SIEM", s: "gap" },
        { t: "Behavioral analytics; threat hunting", s: "partial", lab: ["runtime", "Runtime Security"] },
        { t: "Incident response: isolate node, drain, freeze evidence, rotate credentials", s: "gap" },
        { t: "Persistence paths: mutating webhooks, CronJobs, DaemonSets, cluster-admin bindings", s: "gap" },
        { t: "Backup / restore security (Velero encryption, RBAC on backups)", s: "gap" },
      ],
    },
    {
      n: 11, id: "cloud", name: "Cloud / platform and multi-cluster", layer: "Cloud",
      blurb: "The outer C in the 4Cs — the account and fleet around the cluster.",
      items: [
        { t: "Shared responsibility (EKS/GKE/AKS vs self-managed)", s: "gap" },
        { t: "Private clusters; control-plane authorized networks", s: "gap" },
        { t: "Node IAM vs workload identity", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Cloud audit logs + GuardDuty / Defender / SCC", s: "gap" },
        { t: "Cluster API security", s: "gap" },
        { t: "Multi-cluster: kubeconfig sprawl, fleet policy", s: "gap" },
        { t: "GitOps security (Argo CD / Flux): SSO, AppProject RBAC, repo credentials, unsigned manifests", s: "gap" },
        { t: "Air-gapped clusters; binary verification", s: "gap" },
      ],
    },
    {
      n: 12, id: "threats", name: "Threat model and common attack paths", layer: "Cluster",
      blurb: "NSA/CISA names three sources: supply chain, external attackers, insiders. Defense, not exploit recipes.",
      items: [
        { t: "Stolen kubeconfig / leaked ServiceAccount token", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Overprivileged SA → create privileged pod → node", s: "partial", lab: ["rbac", "RBAC Lab"] },
        { t: "Unauthenticated kubelet / read-only port", s: "lab", lab: ["cluster-hardening", "CIS Auditor"] },
        { t: "SSRF to cloud metadata → node credentials", s: "deep", lab: ["authn", "AuthN Deep Dive"] },
        { t: "Unsigned / poisoned image", s: "deep", lab: ["supply-deep", "Supply Chain Deep Dive"] },
        { t: "Mutating webhook as persistence", s: "gap" },
        { t: "Cryptomining DaemonSet", s: "partial", lab: ["runtime", "Runtime Security"] },
        { t: "Ingress controller CVEs (large attack surface)", s: "gap" },
        { t: "Confused deputy via aggregated ClusterRoles", s: "gap" },
      ],
    },
  ];

  let mapFilter = "all";
  let mapOpen = { 1: true };

  function itemVisible(it) {
    if (mapFilter === "all") return true;
    return it.s === mapFilter;
  }
  function domainVisible(d) {
    return d.items.some(itemVisible);
  }
  function counts() {
    const all = CATALOG.flatMap(d => d.items);
    return {
      all: all.length,
      lab: all.filter(i => i.s === "lab").length,
      deep: all.filter(i => i.s === "deep").length,
      partial: all.filter(i => i.s === "partial").length,
      gap: all.filter(i => i.s === "gap").length,
    };
  }

  function renderSecmap() {
    const c = counts();
    const filt = (id, label, n) =>
      `<button data-filt="${id}" class="${mapFilter===id?"on":""}">${label} <span class="badge-count">${n}</span></button>`;
    $("#view-secmap").innerHTML = `
      <h2 class="title">Kubernetes Security Map</h2>
      <p class="subtitle">Every major Kubernetes security topic in one place — CKS curriculum, NSA/CISA hardening, CIS Benchmark, and the <b>4Cs</b> (Cloud → Cluster → Container → Code). Status shows what KubeLab already simulates. Deep dives: <b>AuthN &amp; bound tokens</b> and <b>Supply chain (digest, Cosign, SLSA)</b>.</p>

      <div class="fourcs">
        <div class="c"><div class="cn">☁️ Cloud</div><div class="cd">Account, IAM, private API, metadata, fleet</div><span class="arr">›</span></div>
        <div class="c"><div class="cn">☸️ Cluster</div><div class="cd">AuthN/AuthZ, admission, etcd, kubelet, NetworkPolicy</div><span class="arr">›</span></div>
        <div class="c"><div class="cn">📦 Container</div><div class="cd">securityContext, PSS, runtime, sandbox</div><span class="arr">›</span></div>
        <div class="c"><div class="cn">🧩 Code</div><div class="cd">Images, SBOM, Cosign, CI, GitOps</div></div>
      </div>
      <p class="hint" style="margin-top:-8px;margin-bottom:16px">A cluster can be perfectly configured and still be unsafe if the cloud account, node OS, image, or application code is not.</p>

      <div class="legend">
        <span><span class="st deep">deep</span> interactive deep dive</span>
        <span><span class="st lab">lab</span> survey lab</span>
        <span><span class="st partial">partial</span> touched in a lab</span>
        <span><span class="st gap">gap</span> no lab yet</span>
      </div>
      <div class="map-filters">
        ${filt("all","All",c.all)}${filt("deep","Deep dive",c.deep)}${filt("lab","Has lab",c.lab)}${filt("partial","Partial",c.partial)}${filt("gap","Gap",c.gap)}
      </div>
      <div class="row" style="margin-bottom:14px">
        <button class="btn" data-goto="authn">🪪 AuthN Deep Dive</button>
        <button class="btn" data-goto="supply-deep">📦 Supply Chain Deep Dive</button>
        <button class="btn ghost" data-goto="cks-overview">CKS exam domains →</button>
      </div>
      <div id="map-list">
        ${CATALOG.filter(domainVisible).map(d => {
          const items = d.items.filter(itemVisible);
          const open = mapOpen[d.n] ? " open" : "";
          return `<div class="topic${open}" data-n="${d.n}">
            <div class="th"><span class="num">${d.n}</span><b>${d.name}</b><span class="layer">${d.layer}</span><span class="badge-count">${items.length}</span><span style="margin-left:auto;color:var(--muted)">▸</span></div>
            <div class="tb">
              <p class="hint" style="margin-top:0">${d.blurb}</p>
              <ul class="titems">${items.map(it => `<li><span class="st ${it.s}">${it.s}</span><span>${it.t}${it.lab?` <button class="btn sm ghost" data-goto="${it.lab[0]}" style="margin-left:6px">→ ${it.lab[1]}</button>`:""}</span></li>`).join("")}</ul>
            </div>
          </div>`;
        }).join("")}
      </div>
      <div class="expl" style="margin-top:8px"><b>How to use this:</b> filter by status, expand a domain, jump into a lab. Remaining gaps include VAP/CEL, Kyverno, AppArmor, Cilium mTLS, audit-policy authoring, GitOps security, and threat-path walkthroughs.</div>`;
    $$("#view-secmap [data-filt]").forEach(b => b.onclick = () => { mapFilter = b.dataset.filt; renderSecmap(); });
    $$("#view-secmap .th").forEach(h => h.onclick = () => {
      const n = +h.parentElement.dataset.n;
      mapOpen[n] = !mapOpen[n];
      h.parentElement.classList.toggle("open");
    });
    $$("#view-secmap [data-goto]").forEach(b => b.onclick = (e) => { e.stopPropagation(); KL.navigate(b.dataset.goto); });
  }

  /* =======================================================================
   * 2. AUTHENTICATION DEEP DIVE
   * ===================================================================== */
  const CALLERS = [
    { id: "cert", name: "kubectl + client certificate", why: "kubeadm admin.conf: CN = username, O = groups. Common for break-glass local admins." },
    { id: "oidc", name: "kubectl + OIDC id_token", why: "Humans should use OIDC (Dex/Entra/Google), not a shared cluster-admin kubeconfig." },
    { id: "bound", name: "Pod with bound / projected SA token", why: "Default since 1.24. Token is audience-bound, time-bound, and bound to the Pod object." },
    { id: "legacy", name: "Pod with legacy Secret SA token", why: "Pre-1.24 default. Infinite lifetime, stored as a Secret, survives pod deletion — a persistence gift." },
    { id: "bootstrap", name: "kubelet bootstrap token", why: "Used once to join a node. Should be short-lived and in the system:bootstrappers group." },
    { id: "anon", name: "No credentials (anonymous)", why: "If --anonymous-auth=true, this becomes system:anonymous / system:unauthenticated." },
    { id: "impersonate", name: "Authenticated user impersonating an SA", why: "Impersonate-User header. AuthN succeeds as the real user; the request then proceeds as the impersonated identity — if RBAC allows impersonate." },
  ];

  const auth = {
    caller: "bound",
    anonAuth: false,
    oidcOn: true,
    impersonateAllowed: false,
    automount: true,
    tokenKind: "bound", // bound | legacy
    expirySec: 3600,
    audience: "https://kubernetes.default.svc",
    podAlive: true,
    stolen: null,       // { kind, payload, takenAt }
    clock: 0,           // seconds elapsed in the sim
    lastResult: null,
  };

  function b64url(obj) {
    const s = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
    return s.replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
  }
  function fakeJwt(header, payload) {
    return b64url(header) + "." + b64url(payload) + "." + "simulated-signature";
  }
  function nowSec() { return 1710000000 + auth.clock; }

  function boundPayload() {
    return {
      aud: [auth.audience],
      exp: nowSec() + auth.expirySec,
      iat: nowSec(),
      iss: "https://kubernetes.default.svc.cluster.local",
      "kubernetes.io": {
        namespace: "payments",
        pod: { name: "api-7f8d9c", uid: "pod-uid-111" },
        serviceaccount: { name: "api", uid: "sa-uid-222" },
        warnafter: nowSec() + Math.floor(auth.expirySec * 0.8),
      },
      nbf: nowSec(),
      sub: "system:serviceaccount:payments:api",
    };
  }
  function legacyPayload() {
    return {
      iss: "kubernetes/serviceaccount",
      "kubernetes.io/serviceaccount/namespace": "payments",
      "kubernetes.io/serviceaccount/secret.name": "api-token-xyz",
      "kubernetes.io/serviceaccount/service-account.name": "api",
      "kubernetes.io/serviceaccount/service-account.uid": "sa-uid-222",
    };
  }

  function identityFor(caller) {
    switch (caller) {
      case "cert": return { user: "jane", uid: "cert-jane", groups: ["system:authenticated", "dev-leads"], via: "X.509 (CN=jane, O=dev-leads)" };
      case "oidc": return { user: "jane@example.com", uid: "oidc-jane", groups: ["system:authenticated", "sso:platform"], via: "OIDC id_token (iss=dex)" };
      case "bound":
      case "legacy": return { user: "system:serviceaccount:payments:api", uid: "sa-uid-222", groups: ["system:serviceaccounts", "system:serviceaccounts:payments", "system:authenticated"], via: caller === "bound" ? "bound projected SA JWT" : "legacy SA Secret JWT" };
      case "bootstrap": return { user: "system:bootstrap:abcde1", uid: "bootstrap-abcde1", groups: ["system:bootstrappers", "system:authenticated"], via: "bootstrap token" };
      case "anon": return { user: "system:anonymous", uid: "", groups: ["system:unauthenticated"], via: "anonymous authenticator" };
      case "impersonate": return { user: "jane", uid: "cert-jane", groups: ["system:authenticated", "dev-leads"], via: "X.509, then Impersonate-User: system:serviceaccount:kube-system:default" };
      default: return { user: "unknown", uid: "", groups: [], via: "?" };
    }
  }

  function runAuthn() {
    const stages = [
      { id: "tls", name: "TLS", sub: "client cert?" },
      { id: "x509", name: "X.509", sub: "CN / O from cert" },
      { id: "bearer", name: "Bearer JWT", sub: "SA / OIDC / bootstrap" },
      { id: "anon", name: "Anonymous", sub: "--anonymous-auth" },
      { id: "info", name: "user.Info", sub: "username, groups" },
    ];
    const c = auth.caller;
    const hasCert = c === "cert" || c === "impersonate";
    const hasBearer = c === "bound" || c === "legacy" || c === "oidc" || c === "bootstrap";
    const oidcOk = c !== "oidc" || auth.oidcOn;

    let matched = null;
    let denied = null;
    if (hasCert) matched = "x509";
    else if (hasBearer && oidcOk) matched = "bearer";
    else if (c === "oidc" && !auth.oidcOn) denied = "OIDC authenticator is not configured on kube-apiserver (--oidc-issuer-url / AuthenticationConfiguration). Token is ignored.";
    else if (auth.anonAuth) matched = "anon";
    else denied = "No authenticator matched and --anonymous-auth=false → HTTP 401 Unauthorized.";

    const id = denied ? null : identityFor(c);
    let impersonation = null;
    if (!denied && c === "impersonate") {
      if (auth.impersonateAllowed) {
        impersonation = { user: "system:serviceaccount:kube-system:default", groups: ["system:serviceaccounts", "system:serviceaccounts:kube-system"], note: "RBAC allows impersonate. The rest of the request (authZ, admission) sees the impersonated SA, not jane." };
      } else {
        impersonation = { blocked: true, note: "AuthN succeeded as jane, but jane lacks rbac.authorization.k8s.io impersonate on serviceaccounts. Request is authorized as jane, impersonation header is ignored / rejected." };
      }
    }
    return { stages, hasCert, hasBearer, matched, denied, id, impersonation, oidcOk };
  }

  function tokenYaml() {
    if (!auth.automount) {
      return `apiVersion: v1
kind: Pod
metadata:
  name: api-7f8d9c
  namespace: payments
spec:
  serviceAccountName: api
  automountServiceAccountToken: false
  containers:
  - name: api
    image: payments/api@sha256:…`;
    }
    if (auth.tokenKind === "legacy") {
      return `apiVersion: v1
kind: Pod
metadata:
  name: api-7f8d9c
  namespace: payments
spec:
  serviceAccountName: api
  # pre-1.24 default: kube-controller-manager mints a
  # Secret of type kubernetes.io/service-account-token
  volumes:
  - name: api-token-xyz
    secret:
      secretName: api-token-xyz
  containers:
  - name: api
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: api-token-xyz
      readOnly: true`;
    }
    return `apiVersion: v1
kind: Pod
metadata:
  name: api-7f8d9c
  namespace: payments
spec:
  serviceAccountName: api
  # 1.24+ default: kubelet requests a bound token via TokenRequest
  volumes:
  - name: kube-api-access
    projected:
      sources:
      - serviceAccountToken:
          path: token
          expirationSeconds: ${auth.expirySec}
          audience: ${auth.audience}
      - configMap:
          name: kube-root-ca.crt
          items: [{ key: ca.crt, path: ca.crt }]
      - downwardAPI:
          items:
          - path: namespace
            fieldRef: { fieldPath: metadata.namespace }
  containers:
  - name: api
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access
      readOnly: true`;
  }

  function tokenRequestYaml() {
    return `apiVersion: authentication.k8s.io/v1
kind: TokenRequest
spec:
  audiences:
  - ${auth.audience}
  expirationSeconds: ${auth.expirySec}
  boundObjectRef:
    kind: Pod
    apiVersion: v1
    name: api-7f8d9c
    uid: pod-uid-111`;
  }

  function saDisableYaml() {
    return `apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: payments
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: payments
# dedicated SA, still no automount — pods that need the API
# request a projected token explicitly (see YAML on the left)`;
  }

  function evaluateStolen() {
    if (!auth.stolen) return { ok: false, why: "No token copied yet. Click “Copy token from the pod” first." };
    if (!auth.automount && auth.stolen.source === "pod") return { ok: false, why: "automountServiceAccountToken: false — there is no token file in the pod." };
    if (auth.stolen.kind === "legacy") {
      return { ok: true, why: "Legacy SA tokens have no exp, no aud, and are not bound to a Pod. Deleting the pod does not invalidate the Secret. Anyone holding this JWT still authenticates as system:serviceaccount:payments:api until you delete the Secret or the ServiceAccount." };
    }
    // bound
    if (!auth.podAlive) {
      return { ok: false, why: "Bound token references boundObjectRef.uid = pod-uid-111. The Pod is gone, so kube-apiserver rejects the token (TokenReview fails). This is the whole point of bound tokens." };
    }
    const remaining = auth.stolen.exp - nowSec();
    if (remaining <= 0) {
      return { ok: false, why: `Token exp is in the past (expired ${-remaining}s ago). Bound tokens are short-lived; the kubelet rotates them before warnafter.` };
    }
    if (auth.stolen.aud !== auth.audience && auth.stolen.aud !== "https://kubernetes.default.svc") {
      // still valid for its own audience, but apiserver default audience may reject
    }
    const audOk = (auth.stolen.aud === "https://kubernetes.default.svc" || auth.stolen.aud === "https://kubernetes.default.svc.cluster.local");
    if (!audOk) {
      return { ok: false, why: `aud is "${auth.stolen.aud}". kube-apiserver's default TokenReview audience is the API server. A token minted for sts.amazonaws.com (IRSA) will not authenticate to Kubernetes — and that is correct.` };
    }
    return { ok: true, why: `Bound token still valid: pod is alive, exp is ${remaining}s away, audience matches the API server. Steal window = token lifetime (here ${auth.expirySec}s), not “forever”.` };
  }

  const AUTH_QUIZ = [
    { q: "What does Authentication (AuthN) answer, vs Authorization (AuthZ)?",
      opts: ["AuthN: what can you do? AuthZ: who are you?", "AuthN: who are you? AuthZ: what can you do?", "They are the same stage", "AuthN is NetworkPolicy, AuthZ is RBAC"],
      a: 1, e: "AuthN maps credentials to a user.Info (username, uid, groups). AuthZ (RBAC) then decides whether that identity may perform the verb on the resource." },
    { q: "A Kubernetes Secret of type kubernetes.io/service-account-token is dangerous because…",
      opts: ["It is encrypted with KMS by default", "It is a long-lived JWT with no exp and is not bound to a pod — it survives pod deletion", "It can only be used from inside the cluster DNS", "It expires every 10 minutes automatically"],
      a: 1, e: "Legacy SA tokens live in etcd as Secrets, have no expiry, and are not bound to a Pod UID. Copying one is durable persistence. 1.24+ uses projected bound tokens instead." },
    { q: "Which three properties make a projected ServiceAccount token “bound”?",
      opts: ["namespace, labels, annotation", "audience (aud), expiry (exp), boundObjectRef (pod uid)", "RBAC Role, RoleBinding, ClusterRole", "TLS cert, kubeconfig, context"],
      a: 1, e: "The kubelet requests the token via the TokenRequest API with an audience, expirationSeconds, and a boundObjectRef to the Pod. If the pod is deleted or the token is expired / wrong audience, AuthN fails." },
    { q: "If --anonymous-auth=false and a request has no credentials, kube-apiserver returns…",
      opts: ["200 as system:anonymous", "403 Forbidden as system:unauthenticated", "401 Unauthorized — no user.Info is ever built", "It falls through to RBAC"],
      a: 2, e: "Anonymous is itself an authenticator. Disable it and unmatched requests never become a user — they get 401 before RBAC. (If it is enabled, they become system:anonymous in group system:unauthenticated, and RBAC must not grant that group anything.)" },
    { q: "Why set automountServiceAccountToken: false on the default ServiceAccount?",
      opts: ["It makes DNS faster", "Most pods never call the Kubernetes API — mounting a token is free credential theft if the app is RCE'd", "It is required for NetworkPolicy", "It encrypts etcd"],
      a: 1, e: "Every automounted token is a credential sitting on disk in the container. Workloads that do not need the API should not have one. Dedicated SAs with least-privilege RBAC for those that do." },
    { q: "IRSA / GKE Workload Identity uses a projected SA token with a custom audience. Why?",
      opts: ["So the same JWT authenticates to both kube-apiserver and AWS", "The cloud STS exchanges a Kubernetes-bound token whose aud is the cloud (e.g. sts.amazonaws.com) for short-lived cloud creds — the node instance role is never used", "To disable RBAC", "So pods can hit 169.254.169.254"],
      a: 1, e: "The token is minted for the cloud STS audience, so it will not authenticate to kube-apiserver. STS verifies the JWT (issuer = cluster OIDC) and returns temporary cloud credentials. That replaces node-instance-profile / IMDS theft." },
    { q: "Impersonation (Impersonate-User) happens…",
      opts: ["Before TLS", "After AuthN: you must already be an authenticated user who is authorized to impersonate the target", "Inside etcd", "Only for anonymous users"],
      a: 1, e: "The apiserver authenticates the real caller first, then (if the impersonate verb is granted) rewrites user.Info to the impersonated identity for the rest of the request. It is a privileged RBAC permission, not a way to skip AuthN." },
  ];
  let aqIdx = 0, aqScore = 0, aqDone = false;

  async function playAuthn() {
    const r = runAuthn();
    auth.lastResult = r;
    const ids = ["tls","x509","bearer","anon","info"];
    ids.forEach(id => { const el = $("#ast-"+id); if (el) el.className = "auth-st"; });
    for (const id of ids) {
      const el = $("#ast-"+id); if (!el) return;
      el.classList.add("active");
      await sleep(380);
      el.classList.remove("active");
      if (id === "tls") el.classList.add(r.hasCert ? "match" : "skip");
      else if (id === "x509") el.classList.add(r.matched === "x509" ? "pass" : "skip");
      else if (id === "bearer") el.classList.add(r.matched === "bearer" ? "pass" : (auth.caller === "oidc" && !r.oidcOk ? "fail" : "skip"));
      else if (id === "anon") el.classList.add(r.matched === "anon" ? "pass" : (r.denied && !r.matched ? "fail" : "skip"));
      else if (id === "info") el.classList.add(r.denied ? "fail" : "pass");
    }
    renderAuthResult();
  }

  function renderAuthResult() {
    const box = $("#auth-result");
    if (!box) return;
    const r = auth.lastResult || runAuthn();
    if (r.denied) {
      box.innerHTML = `<div class="pill no" style="font-size:14px;padding:6px 12px">401 Unauthorized</div>
        <p style="margin:10px 0 0">${r.denied}</p>
        <div class="expl" style="margin-top:10px"><b>Why this control exists:</b> anonymous access used to be on by default. Combined with overly broad RBAC for system:unauthenticated (or a dashboard that didn't check auth), that is a cluster takeover. Disable anonymous auth on apiserver <i>and</i> kubelet.</div>`;
      return;
    }
    const id = r.id;
    let extra = "";
    if (r.impersonation) {
      extra = r.impersonation.blocked
        ? `<div class="expl" style="margin-top:10px">🪪 Impersonation <b style="color:var(--red)">blocked</b>. ${r.impersonation.note}</div>`
        : `<div class="idcard" style="margin-top:10px"><div class="hint">effective identity after impersonation</div><div class="who">${esc(r.impersonation.user)}</div>
            <div class="kv" style="margin-top:8px"><div>groups</div><div>${r.impersonation.groups.map(esc).join(", ")}</div></div>
            <div class="hint" style="margin-top:8px">${r.impersonation.note}</div></div>`;
    }
    box.innerHTML = `<div class="pill ok" style="font-size:14px;padding:6px 12px">authenticated</div>
      <div class="idcard" style="margin-top:10px">
        <div class="hint">user.Info (what RBAC sees next)</div>
        <div class="who">${esc(id.user)}</div>
        <div class="kv" style="margin-top:8px">
          <div>uid</div><div>${esc(id.uid) || "—"}</div>
          <div>groups</div><div>${id.groups.map(esc).join(", ")}</div>
          <div>authenticator</div><div>${esc(id.via)}</div>
        </div>
      </div>${extra}
      <div class="expl" style="margin-top:10px"><b>Interview take:</b> RBAC never sees a raw token. It sees this user.Info. That is why a leaked SA token is an identity, not “just a string” — and why bound tokens shrink the window and the blast radius.</div>`;
  }

  function jwtHtml(payload, kind) {
    const header = kind === "legacy"
      ? { alg: "RS256", typ: "JWT" }
      : { alg: "RS256", typ: "JWT" };
    const token = fakeJwt(header, payload);
    const [h, p, s] = token.split(".");
    return `<div class="jwt"><span class="hdr">${h}</span>.<span class="pl">${p}</span>.<span class="sig">${s}</span></div>
      <label class="fld">Decoded payload</label>
      <div class="log" style="min-height:auto;max-height:220px">${esc(JSON.stringify(payload, null, 2))}</div>
      <p class="hint" style="margin:8px 0 0">${kind === "legacy"
        ? "No <code>exp</code>, no <code>aud</code>, no <code>kubernetes.io.pod</code>. This JWT is valid until the Secret is deleted."
        : "Has <code>aud</code>, <code>exp</code>, and <code>kubernetes.io.pod.uid</code>. Apiserver rejects it if the pod is gone, the audience is wrong, or the clock is past exp."}</p>`;
  }

  function renderTokenPanels() {
    const mount = $("#tok-yaml"); if (mount) mount.textContent = tokenYaml();
    const tr = $("#tok-req"); if (tr) tr.textContent = tokenRequestYaml();
    const sa = $("#tok-sa"); if (sa) sa.textContent = saDisableYaml();
    const clock = $("#tok-clock"); if (clock) clock.textContent = formatClock(auth.clock);
    const pod = $("#tok-pod");
    if (pod) pod.innerHTML = auth.podAlive
      ? `<span class="pill ok">pod api-7f8d9c Running</span>`
      : `<span class="pill no">pod api-7f8d9c Deleted</span>`;
    const mountState = $("#tok-mount");
    if (mountState) {
      if (!auth.automount) mountState.innerHTML = `<span class="pill warn">no token mounted</span>`;
      else mountState.innerHTML = auth.tokenKind === "bound"
        ? `<span class="pill info">projected bound token · exp ${auth.expirySec}s · aud ${esc(auth.audience.split("//")[1]||auth.audience)}</span>`
        : `<span class="pill no">legacy Secret token · no exp</span>`;
    }
    const stolenBox = $("#tok-stolen");
    if (stolenBox) {
      if (!auth.stolen) stolenBox.innerHTML = `<p class="hint">No token copied. Start the pod (automount on) and click <b>Copy token from the pod</b>.</p>`;
      else stolenBox.innerHTML = jwtHtml(auth.stolen.payload, auth.stolen.kind);
    }
  }

  function formatClock(sec) {
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    return `t+${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(s).padStart(2,"0")}`;
  }

  function stealToken() {
    if (!auth.automount) {
      auth.stolen = null;
      const r = $("#tok-replay"); if (r) r.innerHTML = `<div class="pill no">nothing to copy</div><p>automountServiceAccountToken: false — the container has no token file. An RCE in this app does not get a cluster identity. That is the control.</p>`;
      renderTokenPanels();
      return;
    }
    const kind = auth.tokenKind;
    const payload = kind === "bound" ? boundPayload() : legacyPayload();
    auth.stolen = {
      kind, payload, aud: kind === "bound" ? auth.audience : null,
      exp: kind === "bound" ? payload.exp : Infinity,
      source: "pod",
    };
    renderTokenPanels();
    const r = $("#tok-replay"); if (r) r.innerHTML = `<p class="hint">Token copied. Delete the pod and/or fast-forward time, then replay it against kube-apiserver.</p>`;
  }

  function replayToken() {
    const ev = evaluateStolen();
    const r = $("#tok-replay");
    if (!r) return;
    r.innerHTML = `<div class="pill ${ev.ok?"ok":"no"}" style="font-size:14px;padding:6px 12px">${ev.ok?"AUTHENTICATED as system:serviceaccount:payments:api":"TokenReview failed"}</div>
      <p style="margin:10px 0 0">${ev.why}</p>
      <div class="expl" style="margin-top:10px">${ev.ok
        ? "<b>Why this is bad:</b> a stolen identity outlives the workload. Rotate by deleting the Secret (legacy) or relying on short exp + boundObjectRef (bound). Also: never grant this SA permissions it does not need — see the RBAC lab."
        : "<b>Why this control exists:</b> bound tokens turn “I stole a file from a container” into a short, pod-scoped credential. Combine with automount:false, dedicated SAs, and least-privilege RBAC."}</div>`;
  }

  function renderAuthQuiz() {
    const body = $("#auth-quiz-body"); if (!body) return;
    const prog = $("#auth-quiz-prog");
    if (aqIdx >= AUTH_QUIZ.length) {
      const pct = Math.round(aqScore / AUTH_QUIZ.length * 100);
      if (prog) prog.textContent = `score ${aqScore}/${AUTH_QUIZ.length}`;
      body.innerHTML = `<div style="text-align:center;padding:12px 0"><div class="score" style="color:${pct>=70?"var(--green)":pct>=40?"var(--amber)":"var(--red)"}">${pct}%</div>
        <p>You scored <b>${aqScore}/${AUTH_QUIZ.length}</b>. ${pct>=70?"You can explain AuthN vs AuthZ, bound tokens, and automount in an interview.":"Revisit the simulator — toggle legacy vs bound, steal, delete the pod, replay."}</p>
        <button class="btn" id="aq-restart">↻ Restart quiz</button></div>`;
      $("#aq-restart").onclick = () => { aqIdx=0; aqScore=0; aqDone=false; renderAuthQuiz(); };
      return;
    }
    if (prog) prog.textContent = `Q${aqIdx+1}/${AUTH_QUIZ.length} · score ${aqScore}`;
    const item = AUTH_QUIZ[aqIdx]; aqDone = false;
    body.innerHTML = `<p style="font-weight:600;font-size:14.5px;margin-top:0">${item.q}</p>
      <div id="aq-opts">${item.opts.map((o,i)=>`<button class="quiz-opt" data-i="${i}">${o}</button>`).join("")}</div>
      <div id="aq-expl"></div>`;
    $$("#aq-opts .quiz-opt").forEach(b => b.onclick = () => {
      if (aqDone) return; aqDone = true;
      const i = +b.dataset.i; const ok = i === item.a;
      if (ok) aqScore++;
      $$("#aq-opts .quiz-opt").forEach((x,xi) => { x.disabled = true; if (xi===item.a) x.classList.add("correct"); if (xi===i && !ok) x.classList.add("wrong"); });
      $("#aq-expl").innerHTML = `<div class="expl"><b>${ok?"✓ Correct.":"✗ Not quite."}</b> ${item.e}</div>
        <button class="btn" id="aq-next" style="margin-top:12px">${aqIdx===AUTH_QUIZ.length-1?"See results":"Next question →"}</button>`;
      if (prog) prog.textContent = `Q${aqIdx+1}/${AUTH_QUIZ.length} · score ${aqScore}`;
      $("#aq-next").onclick = () => { aqIdx++; renderAuthQuiz(); };
    });
  }

  function renderAuthn() {
    const r = runAuthn();
    $("#view-authn").innerHTML = `
      <h2 class="title">AuthN Deep Dive — Bound ServiceAccount Tokens</h2>
      <p class="subtitle">Authentication answers <b>who are you?</b> before RBAC answers <b>what can you do?</b> This lab walks a request through the authenticator chain, then compares <b>legacy SA Secrets</b> with <b>projected bound tokens</b> (TokenRequest) — the control that stops a stolen token from living forever.</p>

      <div class="row" style="margin-bottom:16px">
        <button class="btn ghost sm" data-goto="secmap">← Security Map</button>
        <button class="btn ghost sm" data-goto="rbac">RBAC Lab (AuthZ) →</button>
        <button class="btn ghost sm" data-goto="flow">Request Flow →</button>
      </div>

      <!-- 1. chain -->
      <div class="panel" style="margin-bottom:16px"><div class="ph">1. Authenticator chain <span class="hint">kube-apiserver tries these in order until one maps credentials → user.Info</span></div><div class="pb">
        <div class="grid cols-2">
          <div>
            <label class="fld">Caller</label>
            <div class="radio-list" id="caller-list">
              ${CALLERS.map(c => `<label class="${auth.caller===c.id?"on":""}"><input type="radio" name="caller" value="${c.id}" ${auth.caller===c.id?"checked":""}><div><b>${c.name}</b><div class="hint">${c.why}</div></div></label>`).join("")}
            </div>
            <div class="row" style="margin-top:10px">
              <label class="switch"><input type="checkbox" id="a-anon" ${auth.anonAuth?"checked":""}> --anonymous-auth</label>
              <label class="switch"><input type="checkbox" id="a-oidc" ${auth.oidcOn?"checked":""}> OIDC configured</label>
              <label class="switch"><input type="checkbox" id="a-imp" ${auth.impersonateAllowed?"checked":""}> RBAC allows impersonate</label>
            </div>
            <button class="btn" id="a-send" style="margin-top:12px">▶ Send request</button>
          </div>
          <div>
            <div class="auth-stages">
              ${r.stages.map(s => `<div class="auth-st" id="ast-${s.id}"><div class="nm">${s.name}</div><div class="sub">${s.sub}</div></div>`).join("")}
            </div>
            <div id="auth-result"><p class="hint">Pick a caller and send the request. Watch which authenticator matches. Try anonymous with the flag off, OIDC with OIDC disabled, and impersonation with/without the verb.</p></div>
          </div>
        </div>
      </div></div>

      <!-- 2. tokens -->
      <div class="panel" style="margin-bottom:16px"><div class="ph">2. Steal a ServiceAccount token <span class="hint">legacy Secret vs bound projected JWT</span></div><div class="pb">
        <div class="row" style="margin-bottom:12px">
          <label class="switch"><input type="checkbox" id="t-auto" ${auth.automount?"checked":""}> automountServiceAccountToken</label>
          <label class="switch"><input type="checkbox" id="t-bound" ${auth.tokenKind==="bound"?"checked":""}> use bound / projected token (1.24+)</label>
          <span id="tok-pod"></span><span id="tok-mount"></span>
          <span class="hint">sim clock <code id="tok-clock"></code></span>
        </div>
        <div class="row" style="margin-bottom:12px">
          <label class="fld" style="margin:0">expirationSeconds</label>
          <select id="t-exp" style="width:auto"><option value="600" ${auth.expirySec===600?"selected":""}>600 (10 min)</option><option value="3600" ${auth.expirySec===3600?"selected":""}>3600 (1 h)</option><option value="86400" ${auth.expirySec===86400?"selected":""}>86400 (1 d)</option></select>
          <label class="fld" style="margin:0">audience</label>
          <select id="t-aud" style="width:auto;min-width:220px">
            <option value="https://kubernetes.default.svc" ${auth.audience==="https://kubernetes.default.svc"?"selected":""}>https://kubernetes.default.svc (apiserver)</option>
            <option value="sts.amazonaws.com" ${auth.audience==="sts.amazonaws.com"?"selected":""}>sts.amazonaws.com (IRSA)</option>
          </select>
        </div>
        <div class="row" style="margin-bottom:14px">
          <button class="btn sm" id="t-steal">📋 Copy token from the pod</button>
          <button class="btn sm ghost" id="t-del">${auth.podAlive?"🗑 Delete pod":"↺ Recreate pod"}</button>
          <button class="btn sm ghost" id="t-ff">⏩ Fast-forward 1 hour</button>
          <button class="btn sm" id="t-replay">▶ Replay stolen token at kube-apiserver</button>
        </div>
        <div class="cmp">
          <div>
            <label class="fld">Pod spec (what the kubelet actually mounts)</label>
            <textarea rows="16" readonly id="tok-yaml"></textarea>
            <label class="fld">TokenRequest (what the kubelet sends for a bound token)</label>
            <textarea rows="12" readonly id="tok-req"></textarea>
          </div>
          <div>
            <label class="fld">Stolen JWT</label>
            <div id="tok-stolen"></div>
            <label class="fld">Replay result</label>
            <div id="tok-replay" class="expl">Copy, then delete the pod / advance time, then replay. Bound tokens die with the pod or the clock; legacy tokens do not.</div>
          </div>
        </div>
      </div></div>

      <!-- 3. disable default SA -->
      <div class="panel" style="margin-bottom:16px"><div class="ph">3. Disable default automount <span class="hint">most pods never need the API</span></div><div class="pb">
        <div class="grid cols-2">
          <div>
            <p style="margin-top:0;line-height:1.55">Every namespace gets a <code>default</code> ServiceAccount. Until you change it, every Pod automounts a token for that SA. An RCE in a frontend that never calls Kubernetes still yields a cluster identity. Fix it at the SA (all pods) or the Pod spec (one workload).</p>
            <textarea rows="16" readonly id="tok-sa"></textarea>
          </div>
          <div>
            <div class="approach"><h4>① Dedicated SA, least privilege</h4><p>Never use the default SA for workloads that need the API. Create <code>api</code>, bind a Role that can only <code>get/list</code> the objects it needs, nothing else.</p></div>
            <div class="approach"><h4>② automountServiceAccountToken: false</h4><p>On the SA and/or the Pod. If the app needs the API, mount a projected token explicitly (YAML on the left of panel 2).</p></div>
            <div class="approach"><h4>③ Bound + short-lived + right audience</h4><p>expirationSeconds of minutes to an hour, not days. Audience = apiserver for in-cluster clients, or the cloud STS for Workload Identity — never both.</p></div>
            <div class="approach"><h4>④ Don't grant the SA extra verbs</h4><p><code>get secrets</code>, <code>create pods</code>, <code>pods/exec</code>, <code>escalate</code>, <code>bind</code>, <code>impersonate</code> are identity theft amplifiers. Continue in the RBAC lab.</p></div>
          </div>
        </div>
      </div></div>

      <!-- 4. workload identity -->
      <div class="panel" style="margin-bottom:16px"><div class="ph">4. Workload Identity vs node IAM / IMDS</div><div class="pb">
        <div class="wi">
          <div class="box bad">
            <h4>✗ Node instance role + IMDS</h4>
            <p>The node VM has an IAM role. Any pod that can reach <code>169.254.169.254</code> (the metadata service) can steal <b>node</b> credentials — often wide enough to read secrets, pull images, or create nodes. This is the classic cloud-metadata hop after a container RCE.</p>
            <div class="path">pod → 169.254.169.254/latest/meta-data/iam/security-credentials/ → node role keys → cloud APIs</div>
          </div>
          <div class="box good">
            <h4>✓ Workload Identity (IRSA / GKE WI / Azure WI)</h4>
            <p>Annotate the ServiceAccount. The kubelet mints a projected token whose <code>aud</code> is the cloud STS (try it in panel 2). STS verifies the cluster OIDC issuer and returns <b>short-lived, SA-scoped</b> cloud creds. Block IMDS with NetworkPolicy egress deny to link-local.</p>
            <div class="path">pod projected token (aud=sts.amazonaws.com) → STS AssumeRoleWithWebIdentity → role bound to that SA only</div>
          </div>
        </div>
        <div class="expl" style="margin-top:12px"><b>Flags / YAML you would actually use:</b> EKS IRSA = SA annotation <code>eks.amazonaws.com/role-arn</code> + cluster OIDC provider. GKE = <code>iam.gke.io/gcp-service-account</code>. Always pair with a default-deny egress NetworkPolicy so pods cannot scrape IMDS even if WI is misconfigured. Replay an <code>sts.amazonaws.com</code> token against kube-apiserver in panel 2 — it should fail AuthN. That failure is the feature.</div>
      </div></div>

      <!-- 5. interview notes -->
      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="panel"><div class="ph">Why these controls exist</div><div class="pb">
          <details class="faq" open><summary>AuthN vs AuthZ vs admission — say it in one breath</summary><div class="a">TLS proves the channel. Authenticators map credentials to <code>user.Info</code>. RBAC authorizes the verb/resource for that identity. Mutating admission may rewrite the object. Validating admission (PSA/OPA) is the last gate into etcd. A leaked SA token skips nothing except TLS — it still has to pass AuthN (it will, if valid) and then AuthZ as that SA.</div></details>
          <details class="faq"><summary>Why did Kubernetes change the default token in 1.24?</summary><div class="a">Legacy tokens were Secrets in etcd: infinite lifetime, readable by anyone who <code>get secrets</code>, and still valid after the pod died. Bound tokens are issued by the TokenRequest API, stored only as a kubelet-projected file, expire, name an audience, and die with the Pod UID. Persistence via “I copied /var/run/secrets/…/token” shrinks from forever to minutes.</div></details>
          <details class="faq"><summary>Is a bound token enough?</summary><div class="a">No. It is necessary, not sufficient. Still: dedicated SA, automount false unless needed, least-privilege RBAC, no <code>get secrets</code>, block IMDS, and rotate. Bound tokens reduce the <i>window</i> and stop tokens outliving pods. They do not reduce the SA's permissions during that window.</div></details>
          <details class="faq"><summary>What should I disable on a fresh cluster?</summary><div class="a"><code>--anonymous-auth=false</code> on kube-apiserver and kubelet. Do not bind anything to <code>system:unauthenticated</code> or <code>system:anonymous</code>. Turn off automount on the default SA in every namespace. Prefer OIDC for humans over copying <code>admin.conf</code>.</div></details>
        </div></div>
        <div class="panel"><div class="ph">Quiz <span class="badge-count" id="auth-quiz-prog"></span></div><div class="pb" id="auth-quiz-body"></div></div>
      </div>
    `;

    $$("#caller-list input").forEach(i => i.onchange = () => { auth.caller = i.value; renderAuthn(); });
    $("#a-anon").onchange = e => { auth.anonAuth = e.target.checked; };
    $("#a-oidc").onchange = e => { auth.oidcOn = e.target.checked; };
    $("#a-imp").onchange = e => { auth.impersonateAllowed = e.target.checked; };
    $("#a-send").onclick = () => playAuthn();

    $("#t-auto").onchange = e => { auth.automount = e.target.checked; auth.stolen = null; renderTokenPanels(); };
    $("#t-bound").onchange = e => { auth.tokenKind = e.target.checked ? "bound" : "legacy"; auth.stolen = null; renderTokenPanels(); };
    $("#t-exp").onchange = e => { auth.expirySec = +e.target.value; auth.stolen = null; renderTokenPanels(); };
    $("#t-aud").onchange = e => { auth.audience = e.target.value; auth.stolen = null; renderTokenPanels(); };
    $("#t-steal").onclick = stealToken;
    $("#t-del").onclick = () => { auth.podAlive = !auth.podAlive; renderTokenPanels(); const b=$("#t-del"); if(b) b.textContent = auth.podAlive ? "🗑 Delete pod" : "↺ Recreate pod"; };
    $("#t-ff").onclick = () => { auth.clock += 3600; renderTokenPanels(); };
    $("#t-replay").onclick = replayToken;

    $$("#view-authn [data-goto]").forEach(b => b.onclick = () => KL.navigate(b.dataset.goto));
    renderTokenPanels();
    renderAuthQuiz();
  }

  /* =======================================================================
   * REGISTER
   * ===================================================================== */
  KL.addView("secmap", renderSecmap);
  KL.addView("authn", renderAuthn);
})();
