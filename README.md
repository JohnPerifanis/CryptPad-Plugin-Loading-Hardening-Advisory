# CryptPad Plugin Loading Hardening Advisory
## Unrestricted Plugin Loading Enables Server-Side Code Execution and Persistent Modification of Client-Served JavaScript

**Researcher:** John Perifanis  
**Product:** CryptPad  
**Tested version:** CryptPad 2025.3.1  
**Tested deployment:** `cryptpad/cryptpad:version-2025.3.1` Docker deployment  
**Status:** Disputed / not assigned CVE by CISA  
**Related accepted CVE:** CVE-2025-51846  
**Researcher assessment:** Security-significant hardening concern with scope-changing impact potential  
**CISA position:** Technical findings not disputed, but no CVE assignment due to vendor threat model interpretation | CISA also indicated during coordination that it would not dispute another CNA assigning the issue, should another CNA reach a different conclusion under its own scope and assessment criteria.

---

## Executive Summary

During the security testing of CryptPad 2025.3.1, it was identified that CryptPad’s server-side plugin loading mechanism automatically loads JavaScript modules placed under the `lib/plugins/` directory without signature verification, allowlisting, sandboxing, or integrity checks.

Once loaded, a plugin executes inside the CryptPad Node.js server process. It can receive access to the server environment, including sensitive server-side values such as `Env.curvePrivate`, and can interact with internal server functionality. Testing further confirmed that the CryptPad service user can modify JavaScript files served to client browsers, including `/cryptpad/www/common/boot.js`, and that such modifications persist across container restart and are served byte-identically to clients.

The issue was coordinated through CISA VINCE and reviewed by CISA Vulnerability Response and Coordination. CISA did not dispute the technical findings, but declined CVE assignment because the scenario falls outside CryptPad’s declared honest-but-curious threat model and was considered equivalent to a malicious administrator scenario.

This advisory documents the behavior for CryptPad operators and the security community. It presents the technical findings, the vendor and CNA positions, the researcher’s assessment, and practical hardening recommendations.

---

## Important Clarification

This advisory does not claim that CryptPad’s end-to-end encryption is broken under its declared honest-but-curious threat model.

CryptPad’s documented model assumes that the server does not actively modify the client application code served to users. The issue described here concerns what can happen if code execution is introduced into the CryptPad server process through the plugin loading mechanism.

The security concern is that, once a plugin is loaded, it can operate inside the server process and can modify JavaScript that is served to client browsers. This moves the scenario from passive server observation to active server-side modification - a scenario CryptPad itself documents as outside its security guarantees.

---

## Affected Component

The issue concerns the CryptPad server-side plugin loading path and the runtime permissions of the CryptPad service user.

Relevant components:

- `lib/plugin-manager.js`
- `server.js`
- `lib/env.js`
- `/cryptpad/lib/plugins/`
- `/cryptpad/www/`
- `/cryptpad/www/common/boot.js`
- `/cryptpad/customize/`

Tested version:

```text
CryptPad 2025.3.1
Docker image: cryptpad/cryptpad:version-2025.3.1
```

---

## Technical Summary

CryptPad’s plugin manager enumerates the `lib/plugins/` directory and loads plugin modules automatically. The loading behavior does not enforce:

- plugin signing,
- plugin allowlisting,
- integrity verification,
- sandboxing,
- explicit administrative approval at runtime.

If a JavaScript module is placed in the expected plugin directory and the service restarts, CryptPad loads that module as part of the server process.

The main security concern is not only that the plugin can execute server-side code. The more important concern is that the plugin runs with the permissions of the CryptPad service user and can modify JavaScript files that are served to users’ browsers.

This matters because CryptPad’s security model depends on the browser receiving trustworthy client-side code. If the server serves modified JavaScript, the browser may execute attacker-controlled code before encryption takes place.

---

## Evidence 1 - Plugin Loader Automatically Loads JavaScript from `lib/plugins/`

CryptPad’s plugin loading behavior is implemented in `lib/plugin-manager.js`.

Relevant logic:

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
        } catch (err) {
            console.error(err);
        }
    });
} catch (err) { }

module.exports = plugins;
```

The only explicitly excluded file is `README.md`. Any other directory under `lib/plugins/` is processed and its `index.js` is loaded through `require()`.

No signature verification, allowlist, sandbox, or integrity check is performed before loading the plugin.

---

## Evidence 2 - Plugins Receive Access to the Server Environment

CryptPad’s environment object includes sensitive server-side values.

From `lib/env.js`:

```javascript
bearerSecret: void 0,
curvePrivate: curve.secretKey,
curvePublic: Util.encodeBase64(curve.publicKey),
```

From `server.js`:

```javascript
Object.keys(Env.plugins || {}).forEach(name => {
    let plugin = Env.plugins[name];
    if (!plugin.initialize) { return; }
    try { plugin.initialize(Env, "main"); }
    catch (e) {}
});
```

This means that if a plugin implements an `initialize()` function, it receives the full `Env` object. That includes `curvePrivate`, the server’s private signing key.

This does not mean that `curvePrivate` decrypts user documents directly. However, it is still sensitive server-side material, and exposure of this object to unverified plugin code increases the impact of plugin execution.

---

## Evidence 3 - Plugins Can Register Server Commands

CryptPad also allows plugins to register commands in the server command map.

From `server.js`:

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

- command name must be uppercase,
- command value must be a function,
- command name must not already exist.

There is no signature verification or allowlist for which plugin may register such commands.

---

## Evidence 4 - CryptPad Runs as a Non-Root Service User

The tested Docker deployment runs CryptPad as a dedicated non-root user:

```text
uid=4001(cryptpad) gid=4001(cryptpad) groups=4001(cryptpad)
```

This is positive from a hardening perspective, because plugins do not automatically execute as root. However, plugins execute with all permissions of the `cryptpad` service user.

---

## Evidence 5 - `lib/plugins/` Is Writable by the CryptPad Service User

In the tested deployment, the plugin directory is writable by the service user:

```text
PLUGINS_WRITABLE
```

Directory ownership:

```text
755 cryptpad cryptpad /cryptpad/lib/plugins
```

This means any process running as the CryptPad service user can place files in the plugin directory. Once the service restarts, the plugin manager will load them.

---

## Evidence 6 - Plugin Loading Was Verified in a Lab Deployment

A test plugin was placed under:

```text
/cryptpad/lib/plugins/SUPPLY-CHAIN-TEST/index.js
```

After restarting the service, the plugin manager was inspected:

```text
Loaded plugins: [ '_extensions', '_styles', 'SUPPLY_CHAIN_TEST' ]
```

This confirmed that the plugin was automatically loaded by CryptPad’s plugin manager.

---

## Evidence 7 - Server-Side Code Execution Was Demonstrated

A controlled PoC plugin registered a custom challenge command and was triggered through CryptPad’s existing `/api/auth` challenge flow.

The PoC demonstrated server-side code execution by reading `/etc/passwd` and returning its contents in the response.

The full executable PoC is intentionally not included in this advisory to avoid providing directly reusable exploit tooling. The important technical point is that:

- a plugin placed in `lib/plugins/` was loaded on restart,
- the plugin registered a server-side handler,
- the handler was reachable through CryptPad’s existing API flow,
- server-side file read was demonstrated.

This confirms code execution inside the CryptPad server process after plugin placement and restart.

---

## Evidence 8 - Client-Served JavaScript Is Writable by the Service User

The tested deployment confirmed that the CryptPad service user can write to `/cryptpad/www/common/boot.js`:

```text
BOOT_JS_WRITABLE
```

File permissions:

```text
perms:644 owner:cryptpad group:cryptpad /cryptpad/www/common/boot.js
```

This is significant because `boot.js` is JavaScript served to client browsers.

---

## Evidence 9 - On-Disk JavaScript Is Served Byte-Identically to Clients

The SHA256 hash of `/cryptpad/www/common/boot.js` on disk was compared with the file retrieved through HTTP.

On disk:

```text
354f06d2e787fbe68a4fd166c9d43aa38b3cdf4d6e566e7f8b55026c9bd93967  /cryptpad/www/common/boot.js
```

Served over HTTP:

```text
354f06d2e787fbe68a4fd166c9d43aa38b3cdf4d6e566e7f8b55026c9bd93967  /tmp/served-boot.js
```

The hashes matched. This confirms that the file stored on disk is delivered byte-for-byte to clients.

No server-side transformation, signing, or integrity verification was observed in this path.

---

## Evidence 10 - JavaScript Modification Persisted Across Restart

A harmless marker was appended to `/cryptpad/www/common/boot.js`:

```javascript
// persistence test marker XYZ123
```

After restarting the container, the marker was still present:

```text
});
// persistence test marker XYZ123
```

The modified file was also retrieved over HTTP:

```text
});
// persistence test marker XYZ123
```

This confirmed that:

- the modification survived container restart,
- the build process did not overwrite the file,
- the modified file was served to clients.

The test marker was removed after verification.

---

## Evidence 11 - Restart Can Be Forced by CVE-2025-51846

A related vulnerability, CVE-2025-51846, was accepted and published by CISA. That issue allows a remote unauthenticated attacker to degrade or deny service by flooding CryptPad’s WebSocket handling path.

In practical terms, this matters because a plugin placed in `lib/plugins/` is loaded on service restart. If the service is supervised by Docker, systemd, Kubernetes, or similar orchestration, a crash or OOM termination may result in automatic restart.

Therefore, once the plugin file exists, the attacker does not necessarily need to wait for a manual administrator restart. A forced restart can be chained with CVE-2025-51846.

---

## Evidence 12 - npm Postinstall Mechanism Was Tested

A separate mechanism test was performed using a controlled private npm registry. A test package with a `postinstall` script was published to a local Verdaccio registry and installed inside the CryptPad container.

The `postinstall` script wrote a plugin into:

```text
/cryptpad/lib/plugins/SUPPLY-CHAIN-TEST/
```

After restart, the plugin was loaded by CryptPad.

This demonstrated that npm lifecycle scripts can place files into `lib/plugins/` when executed in the CryptPad runtime environment.

Important limitations:

- This test used a private local registry, not the public npm registry.
- No malicious package was published publicly.
- No existing CryptPad dependency was found to contain a `postinstall` script.
- This does not prove that the default dependency tree is directly exploitable today.

The test demonstrates a realistic mechanism, not a default zero-click exploitation path.

---

## What Was Proven

The testing confirmed the following:

1. CryptPad automatically loads plugins from `lib/plugins/`.
2. Plugin loading does not enforce signing, allowlisting, sandboxing, or integrity checks.
3. A loaded plugin can receive the full server `Env` object.
4. The `Env` object includes sensitive server-side values such as `curvePrivate`.
5. Plugins can register server commands.
6. A PoC plugin demonstrated server-side code execution.
7. The CryptPad service user can write to client-served JavaScript.
8. `/cryptpad/www/common/boot.js` is served byte-identically to clients.
9. Modifications to `boot.js` persist across container restart.
10. A related accepted DoS issue, CVE-2025-51846, can force service restart.
11. npm lifecycle scripts can place files into the plugin directory if such a package is installed in the runtime environment.

---

## What Was Not Proven

For accuracy, the following were not proven:

1. No independent unauthenticated file-write vulnerability to `lib/plugins/` was identified.
2. No path traversal, Zip Slip, or arbitrary upload primitive was found that writes directly to `lib/plugins/`.
3. No existing CryptPad dependency was found to contain a `postinstall` script.
4. No malicious package was published to the public npm registry.
5. The npm postinstall test demonstrated the mechanism, not a default exploitable supply-chain compromise.
6. The issue remains dependent on the prerequisite that an attacker can place a JavaScript file in the plugin directory or otherwise influence plugin placement.

---

## CryptPad Threat Model Context

CryptPad’s documented security model is based on an honest-but-curious server assumption. Under that model, the server may observe stored encrypted data but does not actively modify the client application served to users.

CryptPad’s own threat model states:

> “CryptPad uses a server not only to store the data, but also to provide the client application (i.e. the JavaScript code) to the users. The users must consequently trust the server to provide the correct application since no security guarantees can be established otherwise.”

CryptPad’s security blog further states:

> “If you receive bogus code from this server, you cannot establish any security, as this bogus code may, as an example, send all your documents in plaintext to the server. Hence, you must trust the server to not run any active attacks (i.e., not to run a modified CryptPad server software).”

CryptPad’s “Malicious JavaScript” user story also describes the same scenario:

> “As a state actor, I want to seize a heavily used CryptPad server and serve malicious JavaScript because I can actively collect the keys to every document when users visit the site.”

These statements are important because they confirm that server-served malicious JavaScript is not merely theoretical. CryptPad’s own documentation identifies it as a scenario that collapses the security guarantees of the application.

---

## Vendor Position

CryptPad’s position during coordinated disclosure was that plugin installation requires server access and that a person capable of writing to the plugin directory can already tamper with the CryptPad codebase.

CryptPad stated that this scenario is outside the honest-but-curious model because it represents an active server-side attack. In their view, a malicious administrator or someone with equivalent server write access is already outside the security model.

This advisory does not dispute that CryptPad’s threat model excludes active malicious-server behavior. The point of this advisory is to document the operational and hardening implications of that boundary.

---

## CISA Position

CISA reviewed the issue through VINCE and did not dispute the technical findings.

CISA also indicated during coordination that it would not dispute another CNA assigning the issue, should another CNA reach a different conclusion under its own scope and assessment criteria.

CISA declined CVE assignment because the scenario is outside CryptPad’s declared threat model and was considered equivalent to a malicious administrator. CISA’s position was that a malicious administrator could already tamper with the server, so the plugin mechanism does not provide a meaningful net gain in attacker capability.

CISA stated, in substance, that the technical findings were accepted but that the issue did not meet CISA’s criteria for CVE assignment.

---

## Researcher View on Threat Model Exclusion

The researcher’s position is that a vendor threat model exclusion should not automatically be interpreted as absence of security relevance. A threat model defines what the product claims to defend against. It does not necessarily mean that behavior outside that model has no security impact or no operational hardening value.

In this case, CryptPad’s documentation clearly states that if the server provides modified client-side JavaScript, no security guarantees can be established. The technical evidence shows that a loaded plugin can modify JavaScript served to client browsers. Therefore, even if this scenario is outside CryptPad’s declared honest-but-curious threat model, the resulting impact remains security-significant for operators.

The researcher accepts that CISA, as CNA, may determine that this does not meet its threshold for CVE assignment because the vendor does not claim to defend against a malicious administrator or active server modification. However, the researcher’s assessment is that the behavior still represents a meaningful hardening concern at CryptPad’s most important trust boundary: the boundary between the server that serves application code and the browser that performs client-side encryption.

---

## Researcher Technical Assessment

The technical concern is not only that a plugin can execute code on the CryptPad server. The more important concern is what that code can do after it is loaded.

The plugin-loading mechanism provides a deterministic execution path: any JavaScript module placed under `lib/plugins/` is loaded by `lib/plugin-manager.js` on startup. Once loaded, the plugin executes inside the CryptPad Node.js process and receives access to the server environment through `plugin.initialize(Env, "main")`. This includes sensitive server-side values such as `Env.curvePrivate`.

Testing also confirmed that the CryptPad service user can write to client-served JavaScript files, including `/cryptpad/www/common/boot.js`. A modification to this file persisted across container restart and was served byte-for-byte to HTTP clients. This means that a loaded plugin is not limited to server-side actions; it can also modify the JavaScript delivered to users’ browsers.

This is important because CryptPad’s security model depends on the browser receiving trustworthy client-side code. If the server serves modified JavaScript, that code can run in the user’s browser before encryption takes place. In such an active malicious-server scenario, the attacker may capture plaintext, encryption keys, session material, or alter cryptographic behavior before the normal end-to-end encryption protections apply.

For this reason, the researcher considers the behavior security-significant even though the vendor places active server-side modification outside its stated honest-but-curious threat model. The issue identifies a practical hardening boundary for operators: the plugin directory and the client-served JavaScript paths should be treated as highly sensitive execution surfaces, not ordinary writable application directories.

---

## Researcher CVSS Assessment

If scored as a vulnerability despite the vendor threat-model exclusion, the researcher assessment is:

```text
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H = 9.1 Critical
```

Rationale:

- `AV:N` - The relevant server functionality is network-facing once a plugin is loaded.
- `AC:L` - The post-load execution path is deterministic.
- `PR:H` - The file-write prerequisite to `lib/plugins/` is conservatively treated as high privilege.
- `UI:N` - Exploitation after plugin placement does not require user interaction. Restart can occur through normal orchestration or be chained with CVE-2025-51846.
- `S:C` - The impact can cross from the server to client browsers by modifying served JavaScript.
- `C:H/I:H/A:H` - Full confidentiality, integrity, and availability impact is possible in the active malicious-server scenario.

This score reflects the researcher’s assessment only. CISA did not assign a CVE and did not publish this score.

A more conservative interpretation could retain `PR:H` and still treat the issue as a high-impact hardening concern rather than a formally assigned CVE.

---

## Practical Interpretation

Operators should not treat the lack of a CVE as meaning there is no operational risk.

The issue documents an important hardening boundary: if an attacker can place files in `lib/plugins/`, the server can load unverified code that can modify client-served JavaScript. Operators should harden the plugin path and served JavaScript paths accordingly.

This is especially important for:

- self-hosted CryptPad deployments,
- deployments using custom plugins,
- deployments using automation or CI/CD that can write into the application directory,
- Docker deployments where runtime paths remain writable,
- environments where restart can be triggered automatically after failure.

---

## Suggested Mitigations for Operators

### 1. Make `lib/plugins/` read-only at runtime

If plugins are not required, the `lib/plugins/` directory should be read-only during normal operation.

If plugins are required, operators should allow changes only through a controlled deployment pipeline.

### 2. Make client-served JavaScript paths read-only

Paths such as the following should not remain writable during runtime unless required for a controlled build or deployment process:

```text
/cryptpad/www/
/cryptpad/www/common/boot.js
/cryptpad/customize/
```

The runtime service should not normally need to modify the JavaScript bundle served to clients.

### 3. Use filesystem integrity monitoring

Operators should monitor sensitive paths for changes:

```text
/cryptpad/lib/plugins/
/cryptpad/www/
/cryptpad/customize/
```

Possible tools include:

- auditd,
- AIDE,
- Tripwire,
- Wazuh,
- EDR filesystem monitoring,
- container image integrity controls.

### 4. Separate build-time and runtime permissions

The build process may require write access to application files. Runtime should not.

A safer deployment pattern is:

1. build application assets in a controlled build stage,
2. package them into an immutable image,
3. run the service with application code mounted read-only.

### 5. Avoid installing npm packages in the runtime container

Operators should avoid running `npm install` inside a live CryptPad runtime container. Any dependency installation should happen during a controlled build process.

This reduces exposure to npm lifecycle scripts such as `postinstall`.

### 6. Use immutable container images

Where possible, run CryptPad from immutable container images and avoid writable application directories inside the container.

Writable volumes should be limited to data paths that truly require persistence.

### 7. Monitor service restarts

Because plugin loading occurs on restart, unexpected service restarts should be monitored and investigated.

This is particularly relevant because CVE-2025-51846 can force service degradation or restart in affected versions.

---

## Suggested Mitigations for CryptPad Upstream

The following changes would reduce risk:

1. Disable plugin loading by default.
2. Require explicit configuration to enable plugins.
3. Implement plugin allowlisting.
4. Require plugin signing or integrity verification.
5. Run plugins in a sandboxed environment with limited access to `Env`.
6. Avoid passing sensitive server-side secrets to plugin initialization unless explicitly required.
7. Make client-served JavaScript read-only at runtime.
8. Add integrity verification for served client bundles.
9. Support a verified-client mechanism such as WEBCAT.
10. Document plugin trust assumptions clearly in operator documentation.

---

## Disclosure and Coordination Timeline

The following timeline summarizes the coordination process.

- **25 May 2025** - Initial private disclosure to CryptPad security team.
- **Summer 2025** - Ongoing communication with CryptPad.
- **21 October 2025** - Researcher follow-up requesting remediation timeline.
- **15 November 2025** - Vendor response disputing severity and framing the issue under the stated threat model.
- **19 November 2025** - Researcher submitted the case to CISA VINCE.
- **5 February 2026** - CISA began review.
- **12 February 2026** - CryptPad joined VINCE coordination.
- **16 February 2026 – 20 March 2026** - Vendor and CISA discussion continued.
- **24 April 2026** - Related CVE-2025-51846 WebSocket DoS was published by CISA.
- **29 April 2026** - MITRE confirmed CVE-2025-51847 was rejected and directed the researcher to the CISA dispute process.
- **1 May 2026** - Researcher submitted additional technical evidence to CISA regarding plugin loading, served JavaScript modification, persistence, and scope change.
- **May 2026** - CISA confirmed it did not dispute the technical findings, but maintained no CVE assignment based on CryptPad’s threat model and malicious administrator interpretation. CISA also indicated that it would not dispute another CNA assigning the issue if another CNA reached a different conclusion.

---

## Related Issue - CVE-2025-51846

CVE-2025-51846 is a separate vulnerability involving unbounded WebSocket frame flooding leading to denial of service. It was accepted and published by CISA.

It is relevant to this advisory because it can force a service restart, and plugin loading occurs on restart.

However, CVE-2025-51846 and the plugin loading behavior are separate issues.

---

## Researcher Position

The researcher respects CryptPad’s right to define its own threat model and CISA’s discretion as CNA.

The purpose of this advisory is not to relitigate the CVE decision, but to document a technically verified behavior that has practical security relevance for operators.

The central point is:

> If unverified code can be loaded into the CryptPad server process, and that code can persistently modify JavaScript served to client browsers, then the most important CryptPad trust boundary — trusted client code delivery — becomes dependent on hardening the plugin and application-code paths.

Even without CVE assignment, this is important operational security information.

---

## Conclusion

The plugin loading mechanism in CryptPad 2025.3.1 provides a powerful server-side extension path. In the tested deployment, that path lacked signing, allowlisting, sandboxing, and integrity verification. A plugin loaded through this mechanism executes in the server process, can access sensitive server environment values, and can modify JavaScript served to every client browser.

CISA did not assign a CVE because the scenario was considered outside CryptPad’s declared threat model and equivalent to malicious administrator behavior. The researcher accepts that this is CISA’s determination.

However, the technical behavior remains important for operators. CryptPad’s own documentation states that if the server provides modified client-side JavaScript, no security guarantees can be established. The testing performed confirms that a loaded plugin can create exactly that condition.

For this reason, operators should treat `lib/plugins/`, `/cryptpad/www/`, and `/cryptpad/customize/` as sensitive execution surfaces and harden them accordingly.

---

## References

CryptPad threat model:

```text
https://blueprints.cryptpad.org/document/threatmodel/
```

Archived:

```text
https://web.archive.org/web/20260501123704/https://blueprints.cryptpad.org/document/threatmodel/
```

CryptPad malicious JavaScript user story:

```text
https://blueprints.cryptpad.org/document/user-stories/malicious-javascript/
```

Archived:

```text
https://web.archive.org/web/20260406213307/https://blueprints.cryptpad.org/document/user-stories/malicious-javascript/
```

CryptPad security blog:

```text
https://blog.cryptpad.org/2024/03/14/Most-Secure-CryptPad-Usage/
```

Archived:

```text
https://web.archive.org/web/20260501124243/https://blog.cryptpad.org/2024/03/14/Most-Secure-CryptPad-Usage/
```

CryptPad whitepaper:

```text
https://blog.cryptpad.org/images/whitepaper.pdf
```

Archived:

```text
https://web.archive.org/web/20260501124512/https://blog.cryptpad.org/images/whitepaper.pdf
```

CryptPad user security documentation:

```text
https://docs.cryptpad.org/en/user_guide/security.html
```

Archived:

```text
https://web.archive.org/web/20260418181447/https://docs.cryptpad.org/en/user_guide/security.html
```

CryptPad source files, version 2025.3.1:

```text
https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/plugin-manager.js
https://github.com/cryptpad/cryptpad/blob/2025.3.1/server.js
https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/env.js
```

Archived:

```text
https://web.archive.org/web/20260501124645/https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/plugin-manager.js
https://web.archive.org/web/20260501125027/https://github.com/cryptpad/cryptpad/blob/2025.3.1/server.js
https://web.archive.org/web/20260501125050/https://github.com/cryptpad/cryptpad/blob/2025.3.1/lib/env.js
```

Related CVE:

```text
CVE-2025-51846
https://www.cve.org/CVERecord?id=CVE-2025-51846
```

---

## Final Note

This advisory is published for operator awareness and hardening guidance.

The technical findings were reviewed through coordinated disclosure. CISA did not dispute the technical evidence, but did not assign a CVE based on its interpretation of the vendor’s threat model and malicious administrator boundary.

The researcher’s view is that, regardless of CVE status, the behavior is security-significant because it affects the trust boundary between the CryptPad server and the client-side code responsible for encryption.


👤 Researcher
John Perifanis
 | Contact: https://www.linkedin.com/in/ioannis-p-9081842b9
