# ThreatLens Security & Privacy Controls

## 1. Untrusted Input Handling
Threat reports and incident descriptions submitted by analysts are treated as untrusted data:
1. **No Code Execution**: Submitted narratives and uploaded documents are parsed strictly as passive textual data. Executable formats (.exe, .dll, .bat, macros) are blocked by the document parser.
2. **Safe Document Parsing**: PDF parsing via `pypdf` extracts text streams passively without executing embedded JavaScript or external launch actions.
3. **HTML Sanitization**: All content rendered on the frontend is escaped by React's standard JSX rendering pipeline. No raw `dangerouslySetInnerHTML` is used for untrusted narrative content.

---

## 2. Technical Indicator Defanging
To prevent security analysts or browser pre-fetch engines from accidentally clicking or resolving malicious links:
- URLs are safely defanged before display (e.g. `https://` becomes `hxxps://`, dots become `[.]`).
- IP addresses and domains are defanged with bracketed dots (e.g. `192[.]0[.]2[.]1`, `evil[.]com`).
- Email addresses are defanged with bracketed at signs (e.g. `user[at]bad[.]com`).
- The application never automatically visits extracted URLs or connects to extracted IP addresses.

---

## 3. Privacy & External Integrations
1. **No Unintentional Data Leakage**: Sensitive report narratives submitted by internal analysts are **never** transmitted to third-party APIs.
2. **Opt-in Enrichment**: External indicator enrichment (VirusTotal / AlienVault OTX) is disabled by default and requires explicit user action ("Query Providers"). Only the sanitized indicator string (e.g., hash or domain) is transmitted.
3. **Secret Isolation**: External API keys (`VIRUSTOTAL_API_KEY`, `ALIENVAULT_OTX_API_KEY`) are stored exclusively in backend environment variables and are never transmitted to frontend clients.
4. **Audit Logging**: All significant actions (investigation creations, indicator status modifications, model retraining, demo data alterations) are recorded in the `audit_events` table for compliance and non-repudiation.
