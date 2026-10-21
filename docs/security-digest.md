# Dependency Security Digest

**Scope:** npm packages we lean on hardest — `lodash`, `axios`, `minimist`
**Source:** GitHub public security advisory database (reviewed advisories, `type: reviewed`)
**Method:** Live queries per package; full advisory records pulled for everything that came back. Each section below lists exactly what the database returned today — no historical counts.

---

## lodash

**Advisories returned today: 1**

### GHSA-r5fr-rjxr-66jc — Code Injection via `_.template` imports key names

- **Advisory ID:** GHSA-r5fr-rjxr-66jc
- **CVE:** CVE-2026-4800
- **Severity:** High (CVSS 3.1 score: 8.1, vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE:** CWE-94 (Improper Control of Generation of Code / Code Injection)
- **Summary:** The fix for CVE-2021-23337 validated the `variable` option in `_.template` but not `options.imports` key names. Both paths flow into the same `Function()` constructor sink, so untrusted imports key names can inject default-parameter expressions that execute arbitrary code at template compilation time. `assignInWith` merging also copies polluted inherited properties into the imports object.
- **Affected version ranges & patched versions:**

| Package | Vulnerable version range | First patched version |
|---|---|---|
| lodash | >= 4.0.0, <= 4.17.23 | 4.18.0 |
| lodash-es | >= 4.0.0, <= 4.17.23 | 4.18.0 |
| lodash-amd | >= 4.0.0, <= 4.17.23 | 4.18.0 |
| lodash.template | >= 4.0.0, < 4.18.0 | 4.18.0 |

- **Remediation:** Upgrade to **4.18.0**. Workaround: never pass untrusted input as key names in `options.imports` — use only developer-controlled, static key names.
- **Reference:** https://github.com/advisories/GHSA-r5fr-rjxr-66jc

---

## axios

**Advisories returned today: 1**

### GHSA-j8rh-479h-cp32 — Header Injection via inherited headers after minimal interceptor

- **Advisory ID:** GHSA-j8rh-479h-cp32
- **CVE:** CVE-2026-101904
- **Severity:** Medium
- **CWEs:** CWE-74 (Injection), CWE-1321 (Prototype Pollution)
- **Summary:** If a request interceptor returns a replacement config object that lacks an own `headers` property, `dispatchRequest()` reads inherited `Object.prototype.headers`. In a process where another vulnerability has polluted `Object.prototype.headers`, axios can send attacker-controlled headers. Note: this is conditional — it requires a prior same-process prototype-pollution primitive plus an interceptor that rebuilds config and omits headers; axios itself does not create the pollution source.
- **Affected version ranges & patched versions:**

| Package | Vulnerable version range | First patched version |
|---|---|---|
| axios | >= 1.0.0, < 1.20.0 | 1.20.0 |

- **Remediation:** Upgrade to **1.20.0**. Workaround: interceptors that rebuild config should always set an own `headers` property (e.g. preserve `config.headers` or set `headers: {}`), or mutate/return the existing null-prototype config.
- **Reference:** https://github.com/advisories/GHSA-j8rh-479h-cp32

---

## minimist

**Advisories returned today: 3**

### GHSA-xvch-5gv4-984h — Prototype Pollution in minimist

- **Advisory ID:** GHSA-xvch-5gv4-984h
- **CVE:** CVE-2021-44906
- **Severity:** Critical (CVSS 3.1 score: 9.8, vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **CWE:** CWE-1321 (Prototype Pollution)
- **Summary:** Minimist prior to 1.2.6 and 0.2.4 is vulnerable to prototype pollution via `setKey()` in `index.js` (lines 69-95).
- **Affected version ranges & patched versions:**

| Package | Vulnerable version range | First patched version |
|---|---|---|
| minimist | >= 1.0.0, < 1.2.6 | 1.2.6 |
| minimist | < 0.2.4 | 0.2.4 |

- **Remediation:** Upgrade to **1.2.6** (or 0.2.4 on the 0.x line).
- **Reference:** https://github.com/advisories/GHSA-xvch-5gv4-984h

### GHSA-vh95-rmgr-6w4m — Prototype Pollution in minimist

- **Advisory ID:** GHSA-vh95-rmgr-6w4m
- **CVE:** CVE-2020-7598
- **Severity:** Medium (CVSS 3.1 score: 5.6, vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L`)
- **CWE:** CWE-1321 (Prototype Pollution)
- **Summary:** Arguments are not properly sanitized, allowing an attacker to modify the prototype of `Object` — e.g. parsing `--__proto__.y=Polluted` adds a `y` property to all objects, and `--__proto__=Polluted` raises an uncaught error and crashes the app. Exploitable if attackers control arguments passed to minimist.
- **Affected version ranges & patched versions:**

| Package | Vulnerable version range | First patched version |
|---|---|---|
| minimist | < 0.2.1 | 0.2.1 |
| minimist | >= 1.0.0, < 1.2.3 | 1.2.3 |

- **Remediation:** Upgrade to **1.2.3** (or 0.2.1 on the 0.x line) or later.
- **Reference:** https://github.com/advisories/GHSA-vh95-rmgr-6w4m

### GHSA-7fhm-mqm4-2wp7 — Withdrawn: ESLint dependencies are vulnerable (ReDoS and Prototype Pollution)

- **Advisory ID:** GHSA-7fhm-mqm4-2wp7
- **Severity:** Medium
- **Status:** **Withdrawn** (2020-04-03) — superseded by GHSA-vh95-rmgr-6w4m (minimist) and GHSA-6chw-6frg-f759 (acorn) after mistakes in the CVE-2020-7598 ingestion. Listed here because it was returned by today's query; treat the replacement advisories as authoritative.
- **Affected version ranges & patched versions (as reported in this withdrawn record):**

| Package | Vulnerable version range | First patched version |
|---|---|---|
| minimist | < 1.2.2 | 1.2.2 |
| acorn | < 5.7.4 | 5.7.4 |
| acorn | >= 6.0.0, < 6.4.1 | 6.4.1 |
| acorn | >= 7.0.0, < 7.1.1 | 7.1.1 |

- **Reference:** https://github.com/advisories/GHSA-7fhm-mqm4-2wp7

---

## Quick action summary

| Package | Advisories today | Highest severity | Upgrade to |
|---|---|---|---|
| lodash | 1 | High | >= 4.18.0 |
| axios | 1 | Medium | >= 1.20.0 |
| minimist | 3 (incl. 1 withdrawn) | Critical | >= 1.2.6 |
