/* ==========================================================================
 * kubelab-supply-deep.js — Supply Chain Security deep dive for KubeLab.
 *
 * Goes past the CKS survey lab (kubelab-cks.js → Supply Chain): tag mutation,
 * Cosign keyless + ClusterImagePolicy identities, SBOM/VEX, SLSA provenance,
 * CI OIDC federation, and Helm chart provenance. Browser-only simulator.
 * ======================================================================== */
(function () {
  "use strict";
  if (!window.KL) { console.error("KubeLab shell (window.KL) not found"); return; }
  const { $, $$, sleep, esc } = window.KL;

  KL.injectCSS(`
    .reg{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; }
    @media (max-width:900px){ .reg{ grid-template-columns:1fr; } }
    .reg .box{ border:1px solid var(--border); border-radius:10px; padding:12px; background:var(--panel-2); }
    .digest{ font-family:var(--mono); font-size:11.5px; color:var(--cyan); word-break:break-all; }
    .pull{ border:1px dashed var(--border); border-radius:8px; padding:10px; margin-top:8px; font-size:12.5px; }
    .gate-row{ display:flex; justify-content:space-between; align-items:center; padding:7px 0; border-bottom:1px solid var(--border); gap:10px; }
    .gate-row small{ display:block; color:var(--muted); font-size:11px; }
    .id-chip{ font-family:var(--mono); font-size:11px; color:var(--cyan); }
  `);

  const GOOD = "sha256:a11ce5c0ffee0001c0de";
  const EVIL = "sha256:e111c1a5c0de0000dead";
  const IDENTITIES = {
    "github-myorg": "https://github.com/myorg/api/.github/workflows/release.yml@refs/heads/main",
    "github-random": "https://github.com/random/pwned/.github/workflows/build.yml@refs/heads/main",
    none: null,
  };

  const BASES = {
    distroless: { pkgs: 0, cves: [] },
    "alpine:3.19": { pkgs: 14, cves: [["CVE-2023-5678", "low", "openssl"]] },
    "node:18": { pkgs: 180, cves: [["CVE-2024-2201", "medium", "glibc"], ["CVE-2023-44487", "high", "nghttp2"], ["CVE-2024-0567", "medium", "gnutls"]] },
    "ubuntu:22.04": { pkgs: 420, cves: [["CVE-2024-1086", "critical", "kernel-headers"], ["CVE-2023-4911", "high", "glibc"], ["CVE-2024-0567", "medium", "gnutls"]] },
  };

  const scd = {
    swapped: false,
    base: "node:18",
    pin: "tag",
    registry: "gcr.io/myorg",
    runAsRoot: true,
    secretInLayer: false,
    sign: "none",          // none | key | keyless
    identity: "none",      // github-myorg | github-random | none
    sbom: false,
    vex: false,            // suppress the high nghttp2 as disputed
    slsa: 0,
    ciAuth: "long-lived",  // long-lived | oidc
    helmSigned: false,
    helmVerify: false,
    pol: {
      requireSig: true,
      requireKeylessMyorg: true,
      requireDigest: true,
      allowedReg: true,
      denyHigh: true,
      requireSbom: true,
      requireSlsa2: true,
      requireOidcCi: false,
    },
  };

  function currentDigest() { return scd.swapped ? EVIL : GOOD; }
  function imageRef(kind) {
    const name = scd.registry + "/api";
    if (kind === "digest") return name + "@" + GOOD;
    return name + ":1.2.0";
  }

  function builtImage() {
    const base = BASES[scd.base];
    let cves = base.cves.slice();
    if (scd.vex) cves = cves.filter(c => c[0] !== "CVE-2023-44487");
    if (scd.swapped && scd.pin === "tag") {
      return {
        digest: EVIL, signed: false, identity: null, slsa: 0, sbom: false,
        cves: [["CVE-2024-evil", "critical", "xmrig cryptominer"]],
        pkgs: 900, registry: "docker.io/random", pin: "tag",
      };
    }
    return {
      digest: scd.pin === "digest" ? GOOD : currentDigest(),
      signed: scd.sign !== "none",
      keyless: scd.sign === "keyless",
      identity: IDENTITIES[scd.identity],
      slsa: scd.slsa,
      sbom: scd.sbom,
      vex: scd.vex,
      cves, pkgs: base.pkgs,
      registry: scd.registry,
      pin: scd.pin,
      runAsRoot: scd.runAsRoot,
      secretInLayer: scd.secretInLayer,
      ciAuth: scd.ciAuth,
    };
  }

  function evaluateGates(img) {
    const high = img.cves.filter(c => c[1] === "critical" || c[1] === "high");
    const p = scd.pol;
    const identOk = img.identity === IDENTITIES["github-myorg"];
    return [
      { on: p.requireSig, name: "Cosign signature present", ok: img.signed, rem: "cosign sign (keyless) in CI; verify at admission." },
      { on: p.requireKeylessMyorg, name: "Keyless identity is github.com/myorg/…", ok: img.signed && img.keyless && identOk, rem: "ClusterImagePolicy authorities.keyless.identities must match your repo, not any Fulcio cert." },
      { on: p.requireDigest, name: "Pinned by digest", ok: img.pin === "digest", rem: "image: repo@sha256:… — tags are mutable." },
      { on: p.allowedReg, name: "Permitted registry gcr.io/myorg", ok: img.registry === "gcr.io/myorg", rem: "Deny docker.io/random and public caches you do not control." },
      { on: p.denyHigh, name: "No critical/high CVEs (Trivy)", ok: high.length === 0, rem: high.length ? `Found ${high.length}: ${high.map(c=>c[0]).join(", ")}. Distroless + VEX for disputed findings.` : "" },
      { on: p.requireSbom, name: "SBOM attached (SPDX/CycloneDX)", ok: img.sbom, rem: "syft packages <image> -o spdx-json | cosign attach sbom" },
      { on: p.requireSlsa2, name: "SLSA provenance ≥ L2", ok: img.slsa >= 2, rem: "Signed provenance from a hosted, isolated build (GitHub + reusable workflows / Tekton Chains)." },
      { on: p.requireOidcCi, name: "CI authenticates with OIDC (no long-lived cloud key)", ok: img.ciAuth === "oidc", rem: "GitHub Actions id-token: write → cloud role. Long-lived keys in repo secrets are supply-chain gold." },
    ].filter(g => g.on);
  }

  function policyYaml() {
    const p = scd.pol;
    return `apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: payments-api
spec:
  images:
  - glob: "${p.allowedReg ? "gcr.io/myorg/**" : "**"}"
  authorities:
${p.requireSig ? `  - ${p.requireKeylessMyorg ? `keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://token.actions.githubusercontent.com
        subjectRegExp: "https://github.com/myorg/.*//.github/workflows/.*"
    ctlog:
      url: https://rekor.sigstore.dev` : `key:
      data: |  # long-lived cosign.pub — prefer keyless
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…
        -----END PUBLIC KEY-----`}` : "  - static:\n      action: pass  # unsigned allowed — do not ship this"}
${p.requireSlsa2 ? `    attestations:
    - name: slsa-provenance
      predicateType: https://slsa.dev/provenance/v1
      policy:
        type: cue
        data: |
          predicateType: "https://slsa.dev/provenance/v1"
          predicate:
            buildDefinition:
              buildType: =~"^https://slsa.dev/"
` : ""}---
# AlwaysPullImages + digest pin in the workload
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: api
        image: ${imageRef(scd.pin === "digest" ? "digest" : "tag")}`;
  }

  function dockerfileYaml() {
    const base = scd.base === "distroless" ? "gcr.io/distroless/static-debian12" : scd.base;
    return `FROM ${base}
${scd.secretInLayer ? "COPY .env /app/.env          # baked secret — forever in the layer\n" : "# secrets via runtime CSI / env from Secret, not COPY\n"}WORKDIR /app
COPY bin/api /app/api
${scd.runAsRoot ? "# USER not set — container runs as root\n" : "USER 65532:65532\n"}ENTRYPOINT ["/app/api"]`;
  }

  function cosignCmd() {
    if (scd.sign === "none") return "# not signed — admission will fail a require-signature policy";
    if (scd.sign === "key") return `cosign sign --key cosign.key ${imageRef("digest")}
# private key in CI secrets = another long-lived credential to leak`;
    return `cosign sign ${imageRef("digest")}
# keyless: Fulcio issues a short-lived cert bound to the GitHub OIDC token
# identity (iss/sub) is what ClusterImagePolicy matches, not a key file`;
  }

  function slsaNote() {
    return {
      0: "L0 — no provenance. Anyone could have built this on a laptop and docker push'd it.",
      2: "L2 — provenance signed by the build service (GitHub Actions). Tampering after build is detectable; the build host is not fully isolated.",
      3: "L3 — unforgeable provenance, isolated / ephemeral builders, hardened against compromise of the build platform. Aim here for production.",
    }[scd.slsa] || "";
  }

  /* ---------- tag-swap simulator ---------- */
  function renderRegistry() {
    const tagNow = currentDigest();
    const tagGood = !scd.swapped;
    $("#scd-reg-viz").innerHTML = `
      <div class="box">
        <div class="hint">registry tag</div>
        <div style="font-weight:700;margin:4px 0">gcr.io/myorg/api:1.2.0</div>
        <div class="digest">${tagNow}</div>
        <div style="margin-top:8px">${tagGood ? `<span class="pill ok">points at the signed build</span>` : `<span class="pill no">retag: now the cryptominer</span>`}</div>
      </div>
      <div class="box">
        <div class="hint">immutable digest (good build)</div>
        <div class="digest">${GOOD}</div>
        <div class="hint" style="margin-top:6px">cosign signed · keyless · github.com/myorg · SLSA L3 · distroless</div>
        <span class="pill ok" style="margin-top:8px">trusted</span>
      </div>
      <div class="box">
        <div class="hint">attacker image</div>
        <div class="digest">${EVIL}</div>
        <div class="hint" style="margin-top:6px">unsigned · docker.io/random/xmrig · no SBOM</div>
        <span class="pill no" style="margin-top:8px">poison</span>
      </div>`;
    const tagPull = scd.swapped ? EVIL : GOOD;
    const tagBad = scd.swapped;
    $("#scd-pulls").innerHTML = `
      <div class="pull"><b>Deployment A</b> — <code>image: gcr.io/myorg/api:1.2.0</code>
        <div class="hint">kubelet resolves the tag at pull time</div>
        <div style="margin-top:6px">pulls <span class="digest">${tagPull}</span> ${tagBad ? `<span class="pill no">compromised</span>` : `<span class="pill ok">expected</span>`}</div>
      </div>
      <div class="pull"><b>Deployment B</b> — <code>image: gcr.io/myorg/api@${GOOD}</code>
        <div class="hint">digest is content-addressed; retag cannot move it</div>
        <div style="margin-top:6px">pulls <span class="digest">${GOOD}</span> <span class="pill ok">unchanged</span></div>
      </div>`;
    $("#scd-swap-note").innerHTML = scd.swapped
      ? `<div class="expl"><b>What just happened:</b> whoever can <code>docker push …:1.2.0</code> (stolen CI key, public tag on docker.io, or a compromised registry credential) silently replaced the bits behind the tag. Runtime controls (PSS, NetworkPolicy, non-root) still run — on the miner's binary. Pinning by digest, Cosign verification, and a permitted-registry policy each stop this independently. Try them in panel 2.</div>`
      : `<p class="hint" style="margin:0">Click <b>Retag :1.2.0 → attacker digest</b>. Watch Deployment A follow the tag and Deployment B stay put. This is why tags are not an identity.</p>`;
  }

  /* ---------- admission ---------- */
  async function runAdmit() {
    const img = builtImage();
    const gates = evaluateGates(img);
    const stages = ["Build", "SBOM", "Sign", "Scan", "Provenance", "Admit"];
    stages.forEach((_, i) => { const s = $("#scd-st-"+i); if (s) s.className = "stage"; });
    const stageOk = [
      !img.secretInLayer,
      !scd.pol.requireSbom || img.sbom,
      !scd.pol.requireSig || img.signed,
      !scd.pol.denyHigh || img.cves.every(c => c[1] !== "critical" && c[1] !== "high"),
      !scd.pol.requireSlsa2 || img.slsa >= 2,
      gates.every(g => g.ok),
    ];
    for (let i = 0; i < stages.length; i++) {
      const s = $("#scd-st-"+i); if (!s) return;
      s.classList.add("active"); await sleep(280); s.classList.remove("active");
      s.classList.add(stageOk[i] ? "pass" : "fail");
    }
    const admit = gates.every(g => g.ok);
    const dfFails = [];
    if (img.runAsRoot) dfFails.push("runs as root (no USER)");
    if (img.secretInLayer) dfFails.push("secret baked into a layer (COPY .env)");
    if (scd.base !== "distroless" && scd.base !== "alpine:3.19") dfFails.push(`fat base ${scd.base} — ${img.pkgs} packages`);
    $("#scd-result").innerHTML =
      `<div class="pill ${admit?"ok":"no"}" style="font-size:14px;padding:8px 14px">${admit?"✓ ADMITTED by ClusterImagePolicy":"✗ DENIED by ClusterImagePolicy"}</div>`
      + `<div class="findings" style="margin-top:12px">${gates.map(g=>`<div class="f"><span class="sev ${g.ok?"pass":"high"}">${g.ok?"PASS":"FAIL"}</span><div><b>${g.name}</b>${g.ok?"":`<div class="hint" style="margin-top:3px">${g.rem}</div>`}</div></div>`).join("")}</div>`
      + (img.cves.length ? `<label class="fld">Trivy / Grype for this image</label>${img.cves.map(c=>`<div class="chk"><span class="sev ${c[1]}">${c[1].toUpperCase()}</span><div><code>${c[0]}</code> <span class="hint">(${c[2]})${scd.vex && c[0]==="CVE-2023-44487"?" — would be suppressed by VEX":""}</span></div></div>`).join("")}` : `<p class="hint" style="margin-top:10px">Trivy: no known CVEs in <code>${esc(scd.base)}</code>.</p>`)
      + `<label class="fld">Dockerfile / Kubesec static analysis</label>`
      + (dfFails.length ? dfFails.map(f=>`<div class="chk"><span class="sev medium">WARN</span><div>${f}</div></div>`).join("") : `<div class="chk"><span class="sev pass">PASS</span><div>non-root USER, no baked secrets, minimal base</div></div>`)
      + `<div class="expl" style="margin-top:10px"><b>Identity in the signature:</b> <span class="id-chip">${esc(img.identity || "(unsigned)")}</span><br>${slsaNote()}${scd.swapped && img.pin==="tag" ? "<br><b>Tag was swapped:</b> admission evaluated the attacker digest because the workload still names <code>:1.2.0</code>." : ""}</div>`;
  }

  function syncPolicyYaml() {
    const el = $("#scd-pol-yaml"); if (el) el.textContent = policyYaml();
    const df = $("#scd-df"); if (df) df.textContent = dockerfileYaml();
    const cg = $("#scd-cosign"); if (cg) cg.textContent = cosignCmd();
  }

  /* ---------- helm ---------- */
  function helmResult() {
    const box = $("#scd-helm-out"); if (!box) return;
    if (!scd.helmVerify) {
      box.innerHTML = `<div class="pill warn">helm install api ./api-1.2.0.tgz</div><p class="hint">No <code>--verify</code>. A swapped .tgz (or a chart from an unsigned repo) installs anyway. Provenance is optional until you require it.</p>`;
      return;
    }
    if (!scd.helmSigned) {
      box.innerHTML = `<div class="pill no">helm install --verify  →  Error: chart provenance is missing or invalid</div><p>The .prov file is a signed provenance over Chart.yaml + the archive digest. Without it, --verify refuses to install. This is the Helm equivalent of Cosign on images.</p>`;
      return;
    }
    box.innerHTML = `<div class="pill ok">helm install --verify api ./api-1.2.0.tgz  →  provenance verified</div>
      <div class="log" style="min-height:auto;margin-top:8px"><span class="ok">sha256:${GOOD.slice(7,19)}…  signed by ciso@myorg.com</span>
<span class="muted">Chart.yaml + values hashed; matches the .tgz.prov OpenPGP signature</span></div>
      <p class="hint">Also: don't <code>helm repo add</code> random HTTP repos; pin chart versions; treat <code>values.yaml</code> (image tags!) with the same digest discipline as Deployments.</p>`;
  }

  /* ---------- quiz ---------- */
  const SCD_QUIZ = [
    { q: "Why is image: nginx:1.25 a supply-chain identity failure?",
      opts: ["Tags are slower to pull", "Tags are mutable — the bits behind :1.25 can be replaced without changing the manifest", "nginx is not distroless", "Admission cannot see tags"],
      a: 1, e: "A tag is a pointer. Whoever can push that tag changes what every cluster that says image: nginx:1.25 will pull. A digest is the bits. Pin @sha256:… and verify a signature over that digest." },
    { q: "Cosign keyless signing binds the signature to…",
      opts: ["A long-lived cosign.key you store in GitHub Secrets", "A short-lived Fulcio cert whose subject is the CI OIDC identity (repo + workflow)", "The node's IAM role", "The Kubernetes ServiceAccount"],
      a: 1, e: "Fulcio issues a certificate from the GitHub/GitLab OIDC token. ClusterImagePolicy matches issuer + subjectRegExp. Stealing a 10-minute cert from a specific workflow is harder than stealing cosign.key." },
    { q: "A ClusterImagePolicy that only checks “a signature exists” (any keyless identity) is weak because…",
      opts: ["Signatures are slow", "An attacker can sign their poisoned image with their own GitHub repo's keyless identity", "Sigstore is deprecated", "It requires SLSA L3"],
      a: 1, e: "Anyone can cosign sign --yes with their own OIDC identity. The policy must constrain identities to YOUR org/repo/workflow. That is the authorities.keyless.identities stanza." },
    { q: "What does an SBOM give you that a CVE scan at build time does not?",
      opts: ["A smaller image", "A bill of materials you can re-query when a new CVE drops next month, plus VEX to mark not-affected", "NetworkPolicy rules", "A TLS certificate"],
      a: 1, e: "The scan is a point in time. The SBOM is the ingredient list. When CVE-2026-… lands, you grep every cluster's attached SBOMs instead of rebuilding blindly. VEX documents “we don't call that function” so you don't page on noise." },
    { q: "SLSA L3 vs L2 in one sentence?",
      opts: ["L3 is more CVEs", "L2 = signed provenance from the build service; L3 = unforgeable provenance from isolated/ephemeral builders", "L3 means distroless", "They are the same"],
      a: 1, e: "L2 detects tampering after the build. L3 assumes the build platform itself may be attacked and still produces trustworthy provenance. Production releases should target L3." },
    { q: "Why is a long-lived AWS_SECRET_ACCESS_KEY in GitHub Actions a supply-chain bug?",
      opts: ["It makes builds slower", "It is an unbounded credential: any workflow, fork PR, or leaked secret can docker push and cosign as you", "AWS forbids it", "It prevents SBOM generation"],
      a: 1, e: "OIDC federation (permissions: id-token: write → AssumeRoleWithWebIdentity) mints a token scoped to that repo/branch/workflow and expires in minutes. Same idea as bound SA tokens, applied to CI." },
    { q: "helm install --verify fails when…",
      opts: ["The cluster is air-gapped", "The chart has no valid .prov provenance signature", "You used a Deployment", "NetworkPolicy is default-deny"],
      a: 1, e: "Helm provenance is an OpenPGP signature over the chart archive. --verify is the chart analogue of cosign verify. Unsigned charts from random HTTP repos are the tag-swap attack at the Helm layer." },
  ];
  let sqIdx = 0, sqScore = 0, sqDone = false;

  function renderScdQuiz() {
    const body = $("#scd-quiz-body"); if (!body) return;
    const prog = $("#scd-quiz-prog");
    if (sqIdx >= SCD_QUIZ.length) {
      const pct = Math.round(sqScore / SCD_QUIZ.length * 100);
      if (prog) prog.textContent = `score ${sqScore}/${SCD_QUIZ.length}`;
      body.innerHTML = `<div style="text-align:center;padding:12px 0"><div class="score" style="color:${pct>=70?"var(--green)":pct>=40?"var(--amber)":"var(--red)"}">${pct}%</div>
        <p>You scored <b>${sqScore}/${SCD_QUIZ.length}</b>. ${pct>=70?"You can explain digest vs tag, keyless identities, SBOM/VEX, SLSA, and CI OIDC in an interview.":"Retag the image, tighten ClusterImagePolicy, and try CI OIDC vs a long-lived key."}</p>
        <button class="btn" id="sq-restart">↻ Restart quiz</button></div>`;
      $("#sq-restart").onclick = () => { sqIdx=0; sqScore=0; sqDone=false; renderScdQuiz(); };
      return;
    }
    if (prog) prog.textContent = `Q${sqIdx+1}/${SCD_QUIZ.length} · score ${sqScore}`;
    const item = SCD_QUIZ[sqIdx]; sqDone = false;
    body.innerHTML = `<p style="font-weight:600;font-size:14.5px;margin-top:0">${item.q}</p>
      <div id="sq-opts">${item.opts.map((o,i)=>`<button class="quiz-opt" data-i="${i}">${o}</button>`).join("")}</div>
      <div id="sq-expl"></div>`;
    $$("#sq-opts .quiz-opt").forEach(b => b.onclick = () => {
      if (sqDone) return; sqDone = true;
      const i = +b.dataset.i; const ok = i === item.a;
      if (ok) sqScore++;
      $$("#sq-opts .quiz-opt").forEach((x,xi) => { x.disabled = true; if (xi===item.a) x.classList.add("correct"); if (xi===i && !ok) x.classList.add("wrong"); });
      $("#sq-expl").innerHTML = `<div class="expl"><b>${ok?"✓ Correct.":"✗ Not quite."}</b> ${item.e}</div>
        <button class="btn" id="sq-next" style="margin-top:12px">${sqIdx===SCD_QUIZ.length-1?"See results":"Next question →"}</button>`;
      if (prog) prog.textContent = `Q${sqIdx+1}/${SCD_QUIZ.length} · score ${sqScore}`;
      $("#sq-next").onclick = () => { sqIdx++; renderScdQuiz(); };
    });
  }

  function bindToggles() {
    const set = (id, fn) => { const el = $("#"+id); if (el) el.onchange = e => { fn(e); syncPolicyYaml(); }; };
    set("scd-base", e => scd.base = e.target.value);
    set("scd-pin", e => scd.pin = e.target.value);
    set("scd-regsel", e => scd.registry = e.target.value);
    set("scd-root", e => scd.runAsRoot = e.target.checked);
    set("scd-secret", e => scd.secretInLayer = e.target.checked);
    set("scd-sign", e => {
      scd.sign = e.target.value;
      if (scd.sign === "none") scd.identity = "none";
      if (scd.sign === "keyless" && scd.identity === "none") scd.identity = "github-myorg";
      renderSupplyDeep();
    });
    set("scd-id", e => scd.identity = e.target.value);
    set("scd-sbom", e => scd.sbom = e.target.checked);
    set("scd-vex", e => scd.vex = e.target.checked);
    set("scd-slsa", e => scd.slsa = +e.target.value);
    set("scd-ci", e => scd.ciAuth = e.target.value);
    ["requireSig","requireKeylessMyorg","requireDigest","allowedReg","denyHigh","requireSbom","requireSlsa2","requireOidcCi"].forEach(k => {
      set("pol-"+k, e => { scd.pol[k] = e.target.checked; });
    });
  }

  function renderSupplyDeep() {
    const p = scd.pol;
    $("#view-supply-deep").innerHTML = `
      <h2 class="title">Supply Chain Deep Dive — Digest, Cosign, SLSA</h2>
      <p class="subtitle">Runtime policy cannot save you from a poisoned image. This lab walks the path from a <b>mutable tag</b> to a <b>ClusterImagePolicy</b> that verifies a Cosign keyless identity, an SBOM, and SLSA provenance — plus CI OIDC and Helm <code>--verify</code>. The survey lab next door is the 5-minute version; this is the interview version.</p>

      <div class="row" style="margin-bottom:16px">
        <button class="btn ghost sm" data-goto="secmap">← Security Map</button>
        <button class="btn ghost sm" data-goto="supplychain">CKS survey lab →</button>
        <button class="btn ghost sm" data-goto="opa">OPA / Admission →</button>
      </div>

      <div class="panel" style="margin-bottom:16px"><div class="ph">1. The tag-swap attack <span class="hint">tags are pointers, not identities</span></div><div class="pb">
        <div class="row" style="margin-bottom:12px">
          <button class="btn" id="scd-swap">${scd.swapped ? "↺ Restore tag to the signed digest" : "⚠ Retag :1.2.0 → attacker digest"}</button>
        </div>
        <div class="reg" id="scd-reg-viz"></div>
        <div class="grid cols-2" style="margin-top:12px" id="scd-pulls"></div>
        <div id="scd-swap-note" style="margin-top:12px"></div>
      </div></div>

      <div class="panel" style="margin-bottom:16px"><div class="ph">2. Build, sign, attest — then admit <span class="hint">ClusterImagePolicy is the last gate</span></div><div class="pb">
        <div class="grid cols-2">
          <div>
            <label class="fld">Base image</label>
            <select id="scd-base">${Object.keys(BASES).map(b=>`<option ${b===scd.base?"selected":""}>${b}</option>`).join("")}</select>
            <label class="fld">Workload image reference</label>
            <select id="scd-pin">
              <option value="tag" ${scd.pin==="tag"?"selected":""}>by tag (mutable) — gcr.io/myorg/api:1.2.0</option>
              <option value="digest" ${scd.pin==="digest"?"selected":""}>by digest (immutable) — gcr.io/myorg/api@sha256:…</option>
            </select>
            <label class="fld">Registry we push to</label>
            <select id="scd-regsel"><option ${scd.registry==="gcr.io/myorg"?"selected":""}>gcr.io/myorg</option><option ${scd.registry==="docker.io/random"?"selected":""}>docker.io/random</option></select>
            <div class="row" style="margin-top:10px">
              <label class="switch"><input type="checkbox" id="scd-root" ${scd.runAsRoot?"checked":""}> Dockerfile runs as root</label>
              <label class="switch"><input type="checkbox" id="scd-secret" ${scd.secretInLayer?"checked":""}> COPY .env into the image</label>
            </div>
            <label class="fld">Cosign</label>
            <select id="scd-sign">
              <option value="none" ${scd.sign==="none"?"selected":""}>unsigned</option>
              <option value="key" ${scd.sign==="key"?"selected":""}>cosign sign --key (long-lived)</option>
              <option value="keyless" ${scd.sign==="keyless"?"selected":""}>cosign keyless (Fulcio + GitHub OIDC)</option>
            </select>
            <label class="fld">Keyless identity (iss/sub in the Fulcio cert)</label>
            <select id="scd-id">
              <option value="none" ${scd.identity==="none"?"selected":""}>(none)</option>
              <option value="github-myorg" ${scd.identity==="github-myorg"?"selected":""}>github.com/myorg/api release.yml</option>
              <option value="github-random" ${scd.identity==="github-random"?"selected":""}>github.com/random/pwned (attacker)</option>
            </select>
            <div class="row" style="margin-top:10px">
              <label class="switch"><input type="checkbox" id="scd-sbom" ${scd.sbom?"checked":""}> attach SBOM (Syft SPDX)</label>
              <label class="switch"><input type="checkbox" id="scd-vex" ${scd.vex?"checked":""}> VEX: nghttp2 CVE not-affected</label>
            </div>
            <label class="fld">SLSA provenance</label>
            <select id="scd-slsa">
              <option value="0" ${scd.slsa===0?"selected":""}>L0 — none</option>
              <option value="2" ${scd.slsa===2?"selected":""}>L2 — signed by the build service</option>
              <option value="3" ${scd.slsa===3?"selected":""}>L3 — isolated ephemeral builders</option>
            </select>
            <label class="fld">CI cloud credentials</label>
            <select id="scd-ci">
              <option value="long-lived" ${scd.ciAuth==="long-lived"?"selected":""}>AWS_SECRET_ACCESS_KEY in GitHub Secrets</option>
              <option value="oidc" ${scd.ciAuth==="oidc"?"selected":""}>GitHub OIDC → AssumeRoleWithWebIdentity</option>
            </select>
            <div class="row" style="margin-top:12px">
              <button class="btn" id="scd-run">▶ Build, attest &amp; admit</button>
              <button class="btn ghost" id="scd-harden">🔒 Harden pipeline</button>
            </div>
          </div>
          <div>
            <label class="fld">Admission policy (toggle controls)</label>
            ${[
              ["requireSig","Require Cosign signature"],
              ["requireKeylessMyorg","Require keyless identity github.com/myorg/…"],
              ["requireDigest","Require digest pin"],
              ["allowedReg","Only gcr.io/myorg/**"],
              ["denyHigh","Deny critical/high CVEs"],
              ["requireSbom","Require SBOM"],
              ["requireSlsa2","Require SLSA ≥ L2"],
              ["requireOidcCi","Require CI OIDC (no long-lived key)"],
            ].map(([k,l])=>`<div class="gate-row"><div>${l}</div><label class="switch"><input type="checkbox" id="pol-${k}" ${p[k]?"checked":""}></label></div>`).join("")}
            <div class="pipeline" id="scd-pipe" style="padding:16px 4px;margin-top:12px">${["Build","SBOM","Sign","Scan","Provenance","Admit"].map((s,i)=>`<div class="stage" id="scd-st-${i}"><div class="st-name">${s}</div>${i<5?'<div class="arrow">›</div>':""}</div>`).join("")}</div>
            <div id="scd-result"><p class="hint">Harden the pipeline (or click Harden), then admit. Try: unsigned, attacker keyless identity, tag pin after a retag, fat <code>ubuntu</code> base, long-lived CI key.</p></div>
          </div>
        </div>
        <div class="cmp" style="margin-top:14px">
          <div>
            <label class="fld">Dockerfile (static analysis input)</label>
            <textarea rows="10" readonly id="scd-df"></textarea>
            <label class="fld">cosign in CI</label>
            <textarea rows="5" readonly id="scd-cosign"></textarea>
          </div>
          <div>
            <label class="fld">ClusterImagePolicy (what you actually apply)</label>
            <textarea rows="18" readonly id="scd-pol-yaml"></textarea>
          </div>
        </div>
      </div></div>

      <div class="panel" style="margin-bottom:16px"><div class="ph">3. CI OIDC vs long-lived keys</div><div class="pb">
        <div class="wi">
          <div class="box bad">
            <h4>✗ AWS_SECRET_ACCESS_KEY in GitHub Secrets</h4>
            <p>A static cloud key that can <code>docker push</code> and <code>cosign sign --key</code>. Fork PRs, a leaked Actions log, or a compromised dependency in the workflow can mint production images as you — forever, until someone rotates it.</p>
            <div class="path">workflow → secrets.AWS_SECRET_ACCESS_KEY → ecr:PutImage + cosign.key → cluster pulls :latest</div>
          </div>
          <div class="box good">
            <h4>✓ GitHub OIDC → cloud role + keyless Cosign</h4>
            <p><code>permissions: id-token: write</code>. The workflow gets a JWT whose <code>sub</code> is <code>repo:myorg/api:ref:refs/heads/main</code>. STS / WIF exchanges it for minutes-lived creds. Cosign keyless uses the same JWT so ClusterImagePolicy can require that exact subject.</p>
            <div class="path">id-token → Fulcio cert (iss=token.actions.githubusercontent.com) → Rekor → ClusterImagePolicy identities</div>
          </div>
        </div>
        <div class="expl" style="margin-top:12px"><b>Same pattern as bound SA tokens:</b> short-lived, audience-bound, identity-bound credentials. CI is part of the cluster's trusted computing base. If the pipeline can push, it is production.</div>
      </div></div>

      <div class="panel" style="margin-bottom:16px"><div class="ph">4. Helm provenance <span class="hint">the same attack, one layer up</span></div><div class="pb">
        <div class="row" style="margin-bottom:10px">
          <label class="switch"><input type="checkbox" id="scd-hs" ${scd.helmSigned?"checked":""}> helm package --sign (OpenPGP .prov)</label>
          <label class="switch"><input type="checkbox" id="scd-hv" ${scd.helmVerify?"checked":""}> helm install --verify</label>
        </div>
        <div id="scd-helm-out"></div>
        <div class="log" style="min-height:auto;margin-top:10px"><span class="muted">api-1.2.0.tgz</span>
<span class="muted">api-1.2.0.tgz.prov</span>  ${scd.helmSigned?`<span class="ok"># signed provenance</span>`:`<span class="err"># missing</span>`}
<span class="muted"># values.yaml image: field is still a tag unless you pin the digest there too</span></div>
      </div></div>

      <div class="grid cols-2" style="margin-bottom:16px">
        <div class="panel"><div class="ph">Why these controls exist</div><div class="pb">
          <details class="faq" open><summary>Digest vs tag, in one breath</summary><div class="a">A tag is a mutable pointer in a registry you may not control. A digest is the hash of the image config + layers. Signatures, SBOMs, and SLSA attestations are all over a digest. If the workload still says <code>:1.2.0</code>, admission can still be bypassed on the next pull (unless AlwaysPullImages + a policy that rejects tags).</div></details>
          <details class="faq"><summary>Why “signed by someone” is not enough</summary><div class="a">Sigstore keyless lets <i>anyone</i> with a GitHub account sign. The security is in matching <code>issuer</code> + <code>subjectRegExp</code> to <i>your</i> org and release workflow. An attacker signing from <code>github.com/random/pwned</code> must fail ClusterImagePolicy. Try it in panel 2.</div></details>
          <details class="faq"><summary>SBOM vs VEX vs scan</summary><div class="a">Scan = today's CVEs. SBOM = the ingredient list for tomorrow's CVEs. VEX = “we are not affected because we don't load that .so.” Together they replace “rebuild the world every advisory” with “query, then patch what you actually run.”</div></details>
          <details class="faq"><summary>Where this sits in CKS</summary><div class="a">Supply Chain is 20% of CKS: minimize base image, understand SBOM/CI/registries, sign and validate artifacts, static-analyze workloads (Kubesec/KubeLinter/Trivy). Pair with admission (this policy) and runtime (Falco still matters if something slips through).</div></details>
        </div></div>
        <div class="panel"><div class="ph">Quiz <span class="badge-count" id="scd-quiz-prog"></span></div><div class="pb" id="scd-quiz-body"></div></div>
      </div>
    `;

    $("#scd-swap").onclick = () => { scd.swapped = !scd.swapped; renderRegistry(); };
    $("#scd-run").onclick = () => runAdmit();
    $("#scd-harden").onclick = () => {
      scd.base = "distroless"; scd.pin = "digest"; scd.registry = "gcr.io/myorg";
      scd.runAsRoot = false; scd.secretInLayer = false;
      scd.sign = "keyless"; scd.identity = "github-myorg";
      scd.sbom = true; scd.vex = true; scd.slsa = 3; scd.ciAuth = "oidc";
      scd.helmSigned = true; scd.helmVerify = true;
      Object.keys(scd.pol).forEach(k => scd.pol[k] = true);
      renderSupplyDeep();
      runAdmit();
    };
    $("#scd-hs").onchange = e => { scd.helmSigned = e.target.checked; helmResult(); };
    $("#scd-hv").onchange = e => { scd.helmVerify = e.target.checked; helmResult(); };
    $$("#view-supply-deep [data-goto]").forEach(b => b.onclick = () => KL.navigate(b.dataset.goto));
    bindToggles();
    renderRegistry();
    syncPolicyYaml();
    helmResult();
    renderScdQuiz();
  }

  KL.addView("supply-deep", renderSupplyDeep);
})();
