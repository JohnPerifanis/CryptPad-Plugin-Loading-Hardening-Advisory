# CVE-2025-51847 (Reserved) – Trusted Plugin Auto-Loading Leads to Server-Side Code Execution After Plugin File Placement and Restart

## Status
Reserved identifier. Publication status under review.

## Product
CryptPad

## Tested Version
CryptPad 2025.3.1

## Summary
CryptPad automatically loads JavaScript modules placed in trusted plugin directories (e.g. `./lib/plugins/`) when the service starts. In testing, attacker-controlled code placed in a trusted plugin directory was automatically executed after service restart, and the plugin’s challenge handler then became remotely triggerable through the existing `/api/auth` mechanism.

## Preconditions
This behavior requires:
- the ability to place a JavaScript file into a trusted plugin directory, and
- a subsequent CryptPad service restart.

## Technical Behavior Demonstrated
Testing demonstrated that:
- CryptPad automatically `require()`s and executes plugin code from the trusted plugin path on restart,
- this occurs without allow-listing, integrity verification/signing, or sandboxing,
- plugin `modules.challenge` handlers are exposed through the existing `/api/auth` RPC flow,
- after restart, remote invocation of the attacker-controlled handler resulted in server-side code execution inside the CryptPad Node.js process.

Server-side code execution was verified in a controlled environment by returning the contents of `/etc/passwd`.

## Impact
With the above preconditions met, arbitrary code can execute in the CryptPad server process with the privileges of the service account. This can affect confidentiality, integrity, and availability of the server environment.

## Threat-Model Note
The vendor states that this behavior falls within its 'honest-but-curious / semi-honest server' threat model because writing to the trusted plugin directory already implies server access. Under that interpretation, the issue may be treated as a trusted-code-path / hardening concern rather than a standalone vulnerability.

However, that statement does not apply once an attacker can execute or modify server-served code (including client bundles). CryptPad’s own security material acknowledges that users must trust the server to deliver correct client code and discusses mechanisms such as WEBCAT / verification approaches to reduce that trust.

If an attacker can modify the client code served by the server, then it becomes possible in principle to instrument the browser client and capture plaintext and/or keys before encryption. In that sense, there is no contradiction in the cryptography itself: this is a threat-model boundary issue (semi-honest server vs. actively malicious server).

## Why this remains a meaningful product-level weakness
Even if the file-write prerequisite is treated as a high-privilege boundary, the behavior remains a concrete product-level weakness:
- unverified code from a trusted plugin path is automatically executed on restart,
- that code becomes remotely triggerable through an existing RPC surface,
- and the mitigations are product-level (disable-by-default, allow-listing, integrity verification/signing, sandboxing).

## Vendor / Coordinator Status
- The vendor disputes that this should be treated as a standalone vulnerability.
- CISA declined publication under its criteria.
- CISA stated that it would not dispute another CNA assigning this issue under a different interpretation.




## Disclosure Note
This public reference intentionally omits weaponized exploit code and detailed reproduction tooling. Testing was performed only in a controlled environment.
