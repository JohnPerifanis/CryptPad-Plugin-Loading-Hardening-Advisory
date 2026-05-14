# CryptPad Plugin Loading Hardening Advisory

## Unrestricted Plugin Loading and Client-Side Trust Boundary Risks

**Researcher:** John Perifanis  
**Advisory type:** Hardening advisory / security research note  
**Product:** CryptPad  
**Version tested:** CryptPad 2025.3.1  
**Docker image tested:** `cryptpad/cryptpad:version-2025.3.1`  
**Related published CVE:** CVE-2025-51846 — Unbounded WebSocket Frame Flood Denial of Service  
**CVE status for this issue:** No CVE assigned by CISA  
**CISA position:** Technical findings not disputed; no CVE assignment due to vendor threat-model interpretation  
**Researcher position:** Security-significant hardening concern affecting the server-to-client trust boundary

---

## Executive Summary

During the security research on CryptPad 2025.3.1, I reviewed the server-side plugin loading mechanism and identified a security-relevant hardening concern. CryptPad's plugin loader automatically loads JavaScript modules placed under `lib/plugins/` at server startup. The loading process does not enforce plugin signing, allowlisting, sandboxing, or integrity verification.

A loaded plugin executes inside the CryptPad Node.js process with access to the server environment. In the tested deployment, this included access to server-side environment values such as `Env.curvePrivate`, and the plugin executed as the `cryptpad` service user. That same service user had write access to client-side JavaScript files served to browsers, including `/cryptpad/www/common/boot.js`.

The most important security implication is the trust boundary between the CryptPad server and the browser. CryptPad's own security model depends on users receiving trustworthy client-side JavaScript from the server. In the tested environment, a loaded plugin could modify `boot.js`, and that modified file was served byte-identically to clients. The modification also persisted after container restart.

This issue was coordinated through the responsible disclosure process. CISA reviewed the issue and did not dispute the technical findings. However, CISA declined CVE assignment because the scenario was considered outside CryptPad's declared threat model and equivalent to a malicious administrator case. This advisory is therefore published as a hardening advisory for operators, not as an assigned CVE advisory.

The purpose of this document is to clearly describe the behavior, the evidence collected, the vendor and CNA positions, the researcher's assessment, and practical hardening steps for operators of self-hosted CryptPad deployments.

---

## Advisory Status

This advisory does **not** claim that CISA assigned a CVE for this issue. CISA reviewed the behavior through VINCE and did not dispute the technical findings, but concluded that the case did not meet CISA's criteria for CVE assignment because CryptPad's threat model does not defend against active server-side modification by a malicious administrator.

CISA also indicated during coordination that it would not dispute another CNA assigning the issue, should another CNA reach a different conclusion under its own scope and assessment criteria.

This advisory is published to document the behavior and provide practical hardening guidance for CryptPad operators.

---

## Important Clarification

This advisory does **not** claim that CryptPad's end-to-end encryption is broken under its declared honest-but-curious threat model.

CryptPad's documented model assumes that the server does not actively modify the client application code served to users. The issue described here concerns what can happen if code execution is introduced into the CryptPad server process through the plugin loading mechanism.

The security concern is that, once a plugin is loaded, it can operate inside the server process and can modify JavaScript that is served to client browsers. This moves the scenario from passive server observation to active server-side modification — a scenario CryptPad itself documents as outside its security guarantees.

---

## Affected Component and Tested Environment

The testing was performed on a fresh CryptPad Docker deployment.

| Item | Value |
|---|---|
| Product | CryptPad |
| Tested version | 2025.3.1 |
| Docker image | `cryptpad/cryptpad:version-2025.3.1` |
| Runtime user | `uid=4001(cryptpad)` |
| Relevant path | `/cryptpad/lib/plugins/` |
| Relevant client-side paths | `/cryptpad/www/`, `/cryptpad/www/common/boot.js`, `/cryptpad/customize/` |
| Related accepted issue | CVE-2025-51846 |

The findings below are based on local lab testing against a researcher-controlled CryptPad instance. No third-party CryptPad deployments were tested or affected.

---

## Technical Findings

### 1. Unconditional Plugin Loading

CryptPad's plugin manager loads JavaScript modules from `lib/plugins/` during startup.

Relevant code from `lib/plugin-manager.js`:

```javascript
const fs = require('node:fs');
const plugins = {};

try {
    let pluginsDir = fs.readdirSync(__dirname + '/plugins');
    pluginsDir.forEach((name) => {
        if (name === "README.md") { return; }
        try {
            let plugin = require(`./plugins/${name}/index`);
            plugins[plugin.name] = plugin.modules;
            // ...
        } catch (err) {
            console.error(err);
        }
    });
} catch (err) { /* ... */ }

module.exports = plugins;
```

The only explicit exclusion is `README.md`. Any other directory under `lib/plugins/` is processed, and its `index.js` is loaded with `require()`.

No evidence was found of:

- plugin signing,
- allowlisting,
- sandboxing,
- integrity verification,
- plugin origin verification.

This makes `lib/plugins/` a highly sensitive execution path.

---

### 2. Plugin Access to the Server Environment

A loaded plugin can receive the server environment object through `plugin.initialize(Env, "main")`.

Relevant code from `server.js`:

```javascript
Object.keys(Env.plugins || {}).forEach(name => {
    let plugin = Env.plugins[name];
    if (!plugin.initialize) { return; }
    try { plugin.initialize(Env, "main"); }
    catch (e) {}
});
```

Relevant code from `lib/env.js`:

```javascript
bearerSecret: void 0,
curvePrivate: curve.secretKey,
curvePublic: Util.encodeBase64(curve.publicKey),
```

This means a loaded plugin can receive sensitive server-side environment values during initialization. In particular, `Env.curvePrivate` is present in the environment object passed to plugins.

This does not mean that `curvePrivate` directly decrypts user documents. The concern is that a plugin runs inside the server process and receives sensitive server-side context that ordinary external clients should not receive.

---

### 3. Plugin Command Registration

CryptPad plugins can register new commands in the server command map.

Relevant code from `server.js`:

```javascript
Object.keys(Env.plugins || {}).forEach(name => {
    let plugin = Env.plugins[name];
    if (!plugin.addMainCommands) { return; }
    try {
        let commands = plugin.addMainCommands(Env);
        Object.keys(commands || {}).forEach(cmd => {
            if (cmd !== cmd.toUpperCase()) { return; }
            if (typeof(commands[cmd]) !== "function") { return; }
            if (COMMANDS[cmd]) { return; }
            COMMANDS[cmd] = commands[cmd];
        });
    } catch (e) {}
});
```

The checks are limited to:

- command name is uppercase,
- command value is a function,
- command name does not already exist.

This behavior is part of the plugin system design, but it reinforces that loaded plugins are powerful server-side extensions.

---

### 4. Service User Context

The CryptPad process in the tested Docker deployment ran as a non-root service user:

```text
uid=4001(cryptpad) gid=4001(cryptpad) groups=4001(cryptpad)
```

This is positive from a container-hardening perspective: plugins do not automatically run as root. However, plugins still run with the full privileges of the `cryptpad` service user, which owns and can write to several sensitive application paths.

---

### 5. Plugin Directory Writability

In the tested deployment, the plugin directory was writable by the CryptPad service user:

```text
PLUGINS_WRITABLE
```

The path ownership and permissions were:

```text
755 cryptpad cryptpad /cryptpad/lib/plugins
```

Any process running as the `cryptpad` user can therefore write to the plugin directory.

This is important because any file-write primitive that can place a JavaScript file under `lib/plugins/` becomes a server-side execution primitive on restart.

---

### 6. Automatic Plugin Loading Confirmed

A test plugin was placed under the plugin directory and the service was restarted. The plugin manager then loaded it automatically.

Verification command:

```bash
node -e "const pm = require('/cryptpad/lib/plugin-manager');
console.log('Loaded plugins:', Object.keys(pm));"
```

Observed result:

```text
Loaded plugins: [ '_extensions', '_styles', 'SUPPLY_CHAIN_TEST' ]
```

This confirmed that the plugin was loaded by the plugin manager without signing, allowlisting, or integrity validation.

---

### 7. Remote Code Execution Through Plugin Challenge Flow

The original proof of execution used a plugin that registered a custom challenge command and triggered it through CryptPad's `/api/auth` challenge flow.

The proof demonstrated that once the plugin was placed and loaded:

1. a custom challenge command became reachable,
2. the challenge protocol could be completed remotely,
3. the server executed plugin-side JavaScript,
4. the server returned the contents of `/etc/passwd`.

The full exploit driver is not published in this advisory in order to avoid providing weaponized tooling. The advisory documents the behavior and evidence, but intentionally avoids releasing reusable exploit code.

The practical conclusion is that the plugin mechanism provides a reliable server-side execution path once a JavaScript plugin is placed in `lib/plugins/` and the service is restarted.

---

### 8. Writable Client-Served JavaScript

The `cryptpad` service user had write access to `/cryptpad/www/common/boot.js`:

```bash
docker exec cryptpad_lab test -w /cryptpad/www/common/boot.js && echo WRITABLE
```

Observed result:

```text
WRITABLE
```

File ownership and permissions:

```text
perms:644 owner:cryptpad group:cryptpad /cryptpad/www/common/boot.js
```

This file is part of the JavaScript served to client browsers. Since plugins execute as the same `cryptpad` service user, a loaded plugin can modify this file.

---

### 9. Disk-to-Client Content Verification

The on-disk `boot.js` file was compared with the version served over HTTP.

On disk:

```text
354f06d2e787fbe68a4fd166c9d43aa38b3cdf4d6e566e7f8b55026c9bd93967  /cryptpad/www/common/boot.js
```

Served to client:

```text
354f06d2e787fbe68a4fd166c9d43aa38b3cdf4d6e566e7f8b55026c9bd93967  /tmp/served-boot.js
```

The hashes matched. This confirmed that the file on disk was served byte-identically to clients. No transformation, signing, or Subresource Integrity layer was observed in this path.

---

### 10. Persistence Across Restart

A harmless marker was appended to `/cryptpad/www/common/boot.js` to verify whether changes persisted after restart.

Marker added:

```bash
echo "// persistence test marker XYZ123" >> /cryptpad/www/common/boot.js
```

After container restart:

```text
});
// persistence test marker XYZ123
```

Served over HTTP after restart:

```text
});
// persistence test marker XYZ123
```

This confirmed that modifications to `boot.js` persisted across container restart and continued to be served to clients.

The marker was removed after testing.

---

### 11. Relationship with CVE-2025-51846

CVE-2025-51846 is a separate issue reported during the same research process. It concerns an unbounded WebSocket frame flood that can lead to service degradation or termination.

This relationship matters because plugin loading occurs on service startup. If an attacker has already placed a plugin through any file-write vector, a restart is required for the plugin to load. CVE-2025-51846 demonstrates that restart can be attacker-influenced in affected versions through unauthenticated denial-of-service behavior.

This does **not** remove the file-write prerequisite for the plugin issue. It does, however, reduce the practical assumption that an attacker must wait for a normal administrator-initiated restart.

---

### 12. NPM Postinstall Mechanism Proof

A controlled mechanism test was performed using a local private npm registry (Verdaccio). A test npm package with a `postinstall` script was installed inside the CryptPad container. The `postinstall` script wrote a plugin file under `lib/plugins/`, and the plugin was loaded after restart.

This proved the mechanism that npm postinstall scripts can place files into the plugin directory when executed in the CryptPad runtime environment.

Important limitations:

- the package was served from a private local registry, not the public npm registry,
- no malicious package was published publicly,
- no existing CryptPad dependency with a `postinstall` script was identified,
- this test demonstrates mechanism, not a currently exploitable public supply-chain path.

This evidence is included for completeness but is not the primary basis of the advisory.

---

## Impact

The issue is security-significant because it affects the most important trust boundary in CryptPad: the boundary between the server that serves client-side application code and the browser that performs client-side cryptographic operations.

A loaded malicious plugin can:

- execute JavaScript inside the CryptPad Node.js process,
- access the server environment object,
- read server-side files accessible to the `cryptpad` user,
- register additional server commands,
- modify client-served JavaScript such as `boot.js`,
- persist those modifications across restart,
- cause every connecting browser to execute modified JavaScript.

In an active malicious-server scenario, modified client-side JavaScript can capture plaintext or cryptographic material before encryption occurs in the browser. This is not speculation about CryptPad's cryptography. It is a consequence of the standard web application trust model: browsers execute the JavaScript they receive from the server.

CryptPad's own documentation acknowledges this general risk. The key question is not whether such a scenario is catastrophic — CryptPad agrees it is — but whether it falls inside or outside the product's declared threat model.

---

## Vendor Threat Model Context

CryptPad's published threat model is explicit that users must trust the server to provide correct client-side JavaScript.

From CryptPad's threat model:

> CryptPad uses a server not only to store the data, but also to provide the client application (i.e. the JavaScript code) to the users. The users must consequently trust the server to provide the correct application since no security guarantees can be established otherwise.

From CryptPad's security blog:

> If you receive bogus code from this server, you cannot establish any security, as this bogus code may, as an example, send all your documents in plaintext to the server. Hence, you must trust the server to not run any active attacks (i.e., not to run a modified CryptPad server software).

From CryptPad's "Malicious JavaScript" user story:

> As a state actor, I want to seize a heavily used CryptPad server and serve malicious JavaScript because I can actively collect the keys to every document when users visit the site.

The documented countermeasure in that user story is a verified client mechanism. At the time of testing, such a verified-client mechanism was not present in the tested CryptPad deployment.

This advisory does not claim that CryptPad falsely represents its threat model. Rather, it relies on CryptPad's threat model to explain why the plugin loading path is important for operators to harden.

---

## Vendor Position

CryptPad's position during coordinated disclosure was that plugin installation requires server access and that a person capable of writing to the plugin directory can already tamper with the CryptPad codebase.

CryptPad stated that this scenario is outside the honest-but-curious model because it represents an active server-side attack. In their view, a malicious administrator or someone with equivalent server write access is already outside the security model.

This advisory does not dispute that CryptPad's threat model excludes active malicious-server behavior. The purpose of this advisory is to document the operational and hardening implications of that boundary.

---

## CISA Position

CISA reviewed the issue through VINCE and did not dispute the technical findings.

CISA declined CVE assignment because the behavior was considered outside CryptPad's declared threat model and equivalent to a malicious administrator case. In substance, CISA's position was that a malicious administrator could already modify the server and therefore there was no net gain in attacker capability.

CISA also indicated during coordination that it would not dispute another CNA assigning the issue, should another CNA reach a different conclusion under its own scope and assessment criteria.

This advisory represents CISA's position as accurately as possible: the technical behavior was accepted, but CISA did not consider it CVE-worthy under its assessment criteria.

---

## Researcher Assessment

If this behavior were scored as a vulnerability despite the vendor threat-model exclusion, the researcher's assessment would be:

```text
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H = 9.1 Critical
```

Rationale:

- `AV:N` — The remotely exposed behavior is reachable through network-facing server functionality once a plugin is loaded.
- `AC:L` — The post-load execution path is deterministic.
- `PR:H` — The file-write prerequisite to `lib/plugins/` is conservatively treated as high privilege.
- `UI:N` — Exploitation after plugin placement does not require user interaction. Restart can occur through normal orchestration or be chained with CVE-2025-51846.
- `S:C` — The impact can cross from the server to client browsers by modifying served JavaScript.
- `C:H/I:H/A:H` — Full confidentiality, integrity, and availability impact is possible in the active malicious-server scenario.

This score is presented as the researcher's assessment, not as an assigned CVSS score by CISA.

A more conservative interpretation could retain `PR:H` and treat the issue as a high-impact hardening concern rather than a formally assigned CVE. This advisory intentionally presents both the CISA position and the researcher assessment so operators can make their own risk decision.

---

## Researcher View on Threat Model Exclusion

The researcher's position is that a vendor threat model exclusion should not automatically be interpreted as absence of security relevance. A threat model defines what the product claims to defend against. It does not necessarily mean that behavior outside that model has no security impact or no operational hardening value.

In this case, CryptPad's documentation clearly states that if the server provides modified client-side JavaScript, no security guarantees can be established. The technical evidence shows that a loaded plugin can modify JavaScript served to client browsers. Therefore, even if this scenario is outside CryptPad's declared honest-but-curious threat model, the resulting impact remains security-significant for operators.

The researcher accepts that CISA, as CNA, may determine that this does not meet its threshold for CVE assignment because the vendor does not claim to defend against a malicious administrator or active server modification. However, the researcher's assessment is that the behavior still represents a meaningful hardening concern at CryptPad's most important trust boundary: the boundary between the server that serves application code and the browser that performs client-side encryption.

---

## Practical Interpretation for Operators

Operators should not treat the lack of an assigned CVE as meaning there is no operational risk. The issue documents an important hardening boundary: if an attacker can place files in `lib/plugins/`, CryptPad can load unverified code that can modify client-served JavaScript.

For self-hosted CryptPad deployments, the relevant operational question is:

> Who or what can write to `lib/plugins/`, `/cryptpad/www/`, and `/cryptpad/customize/` at runtime?

If the answer includes deployment automation, shared volumes, package install scripts, other containers, or administrative users who do not require plugin management access, then the deployment should be hardened.

---

## What Was Proven

The following points were directly verified during testing on a lab-controlled CryptPad 2025.3.1 Docker deployment:

- The CryptPad plugin manager unconditionally loads JavaScript modules placed under `lib/plugins/`, excluding only `README.md`.
- Loaded plugins execute inside the CryptPad Node.js server process.
- A loaded plugin receives access to the server `Env` object, including sensitive server-side values such as `curvePrivate`.
- Plugins can register additional server-side commands through the plugin integration points.
- The CryptPad service runs as the non-root `cryptpad` user (`uid=4001`) in the tested Docker deployment.
- The `lib/plugins/` directory is writable by the CryptPad service user.
- A test plugin placed under `lib/plugins/` was automatically loaded after service restart.
- A malicious plugin was able to execute server-side code and return `/etc/passwd` through the CryptPad challenge flow.
- The client-served JavaScript file `/cryptpad/www/common/boot.js` is writable by the CryptPad service user in the tested deployment.
- The on-disk `boot.js` file was byte-identical to the content served over HTTP to clients.
- A harmless modification to `boot.js` persisted across container restart and was served to clients.
- CVE-2025-51846 demonstrated that an unauthenticated WebSocket DoS can force service termination/restart, which is relevant because plugins are loaded on restart.

These points form the technical basis for the advisory. The interpretation of whether this behavior meets the threshold for CVE assignment remains disputed and is documented separately in the CISA and researcher assessment sections.

## What Was Not Proven

The following limitations are important and are included to avoid overstating the finding:

1. **No public-registry supply-chain exploit was performed.**  
   The npm postinstall test used a private local registry. No malicious package was published to the public npm registry.

2. **No existing CryptPad dependency with a postinstall script was identified.**  
   The tested dependency tree did not contain an existing CryptPad dependency with a `postinstall` script that could be directly leveraged.

3. **No independent low-privilege file-write vulnerability was found in CryptPad.**  
   The research did not identify a path traversal, arbitrary upload, Zip Slip, or similar vulnerability that allows a remote low-privilege user to write directly into `lib/plugins/`.

4. **The file-write prerequisite remains important.**  
   CISA's PR:H assessment is reasonable under strict CVSS base scoring.

5. **The advisory is not an assigned CVE advisory.**  
   It is a hardening advisory and security research note.

These limitations do not remove the hardening concern. They define its correct operational scope.

---

## Recommended Hardening Measures

### For CryptPad Operators

1. **Make `lib/plugins/` read-only at runtime.**  
   If plugins are not used, the directory should not be writable by the runtime service account.

2. **Make `/cryptpad/www/` read-only at runtime.**  
   Client-served JavaScript should not be modifiable by the running application unless explicitly required.

3. **Make `/cryptpad/customize/` read-only after deployment.**  
   This directory can affect served content and should be treated as sensitive.

4. **Use filesystem integrity monitoring.**  
   Monitor `lib/plugins/`, `/cryptpad/www/`, and `/cryptpad/customize/` with tools such as `auditd`, AIDE, Tripwire, or equivalent controls.

5. **Separate build-time and runtime permissions.**  
   If files need to be generated during build, they should not remain writable during normal runtime.

6. **Review deployment automation.**  
   Audit npm install steps, CI/CD pipelines, Docker volumes, bind mounts, and any automation that can write into the CryptPad installation directory.

7. **Avoid shared writable volumes.**  
   Do not share writable application-code volumes between CryptPad and unrelated containers or services.

8. **Avoid installing npm packages in the runtime container.**  
   Dependency installation should happen during a controlled build process, not inside a live CryptPad runtime container. This reduces exposure to npm lifecycle scripts such as `postinstall`.

9. **Use immutable container images where possible.**  
   Build application assets in a controlled build stage, package them into an immutable image, and keep application code read-only during normal operation.

10. **Monitor unexpected service restarts.**  
   Plugin loading occurs on startup. Unexpected restarts should be investigated, especially in versions affected by CVE-2025-51846.

11. **Restrict administrative access.**  
   Treat access to the CryptPad installation directory as equivalent to the ability to compromise the instance.

---

### For CryptPad Upstream

1. **Disable plugin loading by default.**  
   Require an explicit configuration flag to enable plugins.

2. **Implement plugin allowlisting.**  
   Only load plugin names explicitly listed in configuration.

3. **Support signed or verified plugins.**  
   Cryptographic verification would reduce the risk of untrusted plugin loading.

4. **Sandbox plugin execution.**  
   Isolate plugins from the main server environment where feasible.

5. **Avoid passing full `Env` to plugins by default.**  
   Provide a minimal plugin API instead of the complete server environment object.

6. **Make client-served JavaScript immutable at runtime.**  
   Runtime processes should not be able to modify static application code.

7. **Explore verified-client mechanisms.**  
   CryptPad's own documentation references approaches such as WEBCAT. This type of mechanism would help address the server-served-code trust problem.

---

## Disclosure and Coordination Timeline

| Date | Event |
|---|---|
| 25 May 2025 | Initial private disclosure to CryptPad security team |
| Summer 2025 | Continued vendor communication |
| 21 Oct 2025 | Researcher follow-up requesting remediation timeline |
| 15 Nov 2025 | Vendor response disputing severity and threat-model applicability |
| 19 Nov 2025 | Researcher submitted case to CISA VINCE |
| 5 Feb 2026 | CISA initial review; related WebSocket DoS issue tracked separately |
| 12 Feb 2026 | Vendor invited to VINCE coordination |
| Feb-Mar 2026 | Vendor, CISA, and researcher coordination through VINCE |
| 22 Apr 2026 | CISA indicated no CVE assignment for plugin loading issue |
| 24 Apr 2026 | CVE-2025-51846 published by CISA for related WebSocket DoS |
| 29 Apr 2026 | MITRE confirmed CVE-2025-51847 rejected and directed to dispute process |
| 1 May 2026 | Researcher submitted additional technical evidence to CISA |
| May 2026 | CISA confirmed it did not dispute the technical findings, but maintained no CVE assignment based on CryptPad's threat model and malicious-administrator interpretation. CISA also indicated that it would not dispute another CNA assigning the issue if another CNA reached a different conclusion. |

---

## References

### CryptPad Documentation

- CryptPad Threat Model:  
  https://blueprints.cryptpad.org/document/threatmodel/

- Archived Threat Model:  
  https://web.archive.org/web/20260501123704/https://blueprints.cryptpad.org/document/threatmodel/

- CryptPad Malicious JavaScript User Story:  
  https://blueprints.cryptpad.org/document/user-stories/malicious-javascript/

- Archived Malicious JavaScript User Story:  
  https://web.archive.org/web/20260406213307/https://blueprints.cryptpad.org/document/user-stories/malicious-javascript/

- CryptPad Security Blog — Most Secure Way To Use CryptPad:  
  https://blog.cryptpad.org/2024/03/14/Most-Secure-CryptPad-Usage/

- Archived Security Blog:  
  https://web.archive.org/web/20260501124243/https://blog.cryptpad.org/2024/03/14/Most-Secure-CryptPad-Usage/

### Source Code References

- `lib/plugin-manager.js` at CryptPad 2025.3.1:  
  https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/plugin-manager.js

- Archived `plugin-manager.js`:  
  https://web.archive.org/web/20260501124645/https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/plugin-manager.js

- `server.js` at CryptPad 2025.3.1:  
  https://github.com/cryptpad/cryptpad/blob/2025.3.1/server.js

- Archived `server.js`:  
  https://web.archive.org/web/20260501125027/https://github.com/cryptpad/cryptpad/blob/2025.3.1/server.js

- `lib/env.js` at CryptPad 2025.3.1:  
  https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/env.js

- Archived `env.js`:  
  https://web.archive.org/web/20260501125050/https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/env.js

### Related CVE

- CVE-2025-51846 — CryptPad Unbounded WebSocket Frame Flood Denial of Service:  
  https://www.cve.org/CVERecord?id=CVE-2025-51846

### Standards

- CVSS v3.1 Specification:  
  https://www.first.org/cvss/v3-1/specification-document

- CVSS v3.1 User Guide:  
  https://www.first.org/cvss/v3-1/user-guide

---

## Final Note

This advisory is intentionally written as a hardening advisory rather than as an assigned CVE advisory. CISA did not dispute the technical evidence, but did not assign a CVE because the behavior was considered outside CryptPad's declared threat model.

The researcher's position is that the behavior remains important for operators to understand, especially for self-hosted deployments where plugin paths, runtime file permissions, deployment automation, or writable application-code paths may increase the practical risk.

The goal of publication is to help operators harden CryptPad deployments and make the server-to-client trust boundary explicit.


👤 Researcher
John Perifanis
 | Contact: https://www.linkedin.com/in/ioannis-p-9081842b9
