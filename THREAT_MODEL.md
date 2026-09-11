# Threat Model — AI-Tuned DLP & Insider Threat Detection Platform

## Objective

**Security objective:** Detect sensitive data (payment-card data, SWIFT/payment messages, customer/account records, API keys and secrets, source code, proprietary business documents) leaving a monitored Windows endpoint via file movement, clipboard, or outbound HTTP — with enough context (user, destination, content classification, confidence) that an analyst could act on the alert.

**Project objective:** Build and evaluate a working hybrid detection pipeline (deterministic rules + local LLM + risk scoring) against synthetic exfiltration scenarios, in a single-machine lab, as a demonstrable cybersecurity engineering portfolio piece.

## Assets (what the simulated organization is protecting)

- Cardholder data (synthetic PANs)
- SWIFT/payment message content (synthetic)
- Customer/account records (synthetic)
- API keys, access tokens, private keys, cloud credentials (synthetic)
- Proprietary source code and internal documents
- The integrity of the detection pipeline itself — see Attack Surface below; the DLP system is also something an attacker might target

## Threat Actors

1. **Malicious insider** — an employee intentionally exfiltrating data for personal gain (selling card data, taking source code to a competitor).
2. **Negligent insider** — an employee who mishandles data without intent to harm (pastes a customer record into a personal chat app, uploads a spreadsheet to a personal cloud drive). In real DLP deployments this generates far more alerts than actual malice does.
3. **Compromised insider** — an external attacker operating through a phished/compromised employee session. From the DLP's vantage point this looks identical to insider behavior, because it *is* happening under the legitimate user's session.

**Scope note:** this lab can faithfully simulate actors 1 and 2, since you are the one generating the test activity. Actor 3 is included in the model because the same detectors apply to it, but actually simulating a compromise (malware, C2, credential theft) is explicitly out of scope for this build — see Lab Limitations.

## Insider-Threat & Exfiltration Scenarios

These map directly onto the Phase 11 test scenarios:

1. Copying customer PII to a personal cloud folder shortly before resignation.
2. Pasting card numbers from an internal system into an external chat/email via the clipboard.
3. Uploading a database export (CSV/SQL dump) to an external HTTP endpoint.
4. Sharing a config file containing live-looking API keys/secrets.
5. Deliberately obfuscating sensitive data (base64, string-splitting, JSON-embedding) to evade keyword/regex filters.
6. Transferring proprietary source code externally.
7. **Control case:** ordinary business communication that superficially resembles the above (mentions a customer by name, discusses "the API," etc.) but contains no actual sensitive data. This is what keeps the false-positive rate honest.

## Trust Boundaries & Data Flow

Referencing the architecture diagram from the project brief, the boundaries that matter:

- **Test Workstation → Endpoint Telemetry Layer:** user-initiated activity is treated as untrusted-by-default; the collector observes but doesn't assume intent.
- **Endpoint Telemetry Layer → Detection/AI backend:** content crossing this boundary is still "untrusted user input" from the AI's point of view — this is where prompt-injection risk lives (Phase 6 / Phase 13).
- **Lab network → simulated external destination:** the local test HTTP server stands in for "the internet." This is the boundary the whole system exists to observe.

## Attack Surface (of the system we're building)

- The local REST API between collectors and backend — if unauthenticated, another local process could inject fake events or read alerts.
- Ollama's local API (port 11434 by default) — must stay bound to localhost; if it's reachable on the Wi-Fi network, that's a real, common misconfiguration.
- The local "exfiltration destination" test server — must never be exposed beyond the lab.
- Prompt injection — if raw suspicious content is dropped straight into the LLM prompt, an insider could craft text that tries to talk the model down to a lower risk score.

## Detection Requirements (derived from the above)

- Deterministic detection must catch structured sensitive data (card numbers + Luhn, SWIFT patterns, secrets) with a low false-positive rate on control-case traffic.
- The AI layer must add coverage the deterministic layer misses (obfuscation, context-dependent sensitivity) — and Phase 12 must *prove* it does, not just assume it.
- Every verdict needs a machine-readable score **and** a human-readable reason (explainability, analyst trust).
- The system must correlate behavior per user over time, not just score single events in isolation — insider threat is usually a pattern, not one action.

## Assumptions & Lab Limitations

- The collector agent is assumed to run with legitimate, sufficient privilege, deployed by "the SOC" (you). Agent self-tampering/uninstall by the insider is a real production DLP concern but is explicitly out of scope here.
- The local LLM's output is never trusted blindly — deterministic detection can raise an alert independently even if the AI disagrees. This is *why* the architecture is hybrid, not AI-only.
- No real network segmentation, no real directory service (AD/LDAP) — "user identity" is a config value, not an authenticated identity from an IdP.
- No adversarial red-team component — obfuscation scenarios are self-generated test data, not an active adversary trying to evade the blue team in real time.
- Detection metrics (Phase 12) will come from a modest synthetic dataset you build — results are indicative for portfolio/interview purposes, not statistically rigorous at production scale.

## Completion Criteria

- [x] Assets, threat actors, and the 7 core scenarios are documented.
- [ ] Every Phase 11 test scenario traces back to one of these threat-model scenarios (verify when we reach Phase 11).
- [ ] Assumptions and limitations are stated clearly enough to defend in an interview (Phase 18).
