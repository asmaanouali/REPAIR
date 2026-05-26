# IR-SAM CWE Scope (frozen for thesis)

**Status:** frozen at end of Phase 0, month 3.
**Owner:** PhD candidate.
**Revision policy:** any change requires supervisor sign-off and a
versioned amendment in this file.

## 1. Scoping principles

A CWE class is **in-scope** for IR-SAM if and only if all of the
following hold:

1. **Interpreter-bounded.** The vulnerability is realized by a host
   program invoking a *sink* `sink(s)` on a string `s` that is passed
   to a downstream **interpreter** with a formal surface grammar
   (SQL parser, OS shell, HTML/DOM parser, LDAP filter compiler,
   XPath compiler, template engine, etc.).
2. **Intent-recoverable.** The benign developer intent that produced
   `s` can be reconstructed as a parameterized program in that
   interpreter's grammar (i.e., the surface string is the projection
   of a higher-level abstract operation).
3. **Safe-API exists.** A parameterizing or contextually-escaping API
   is available in at least one mainstream library or framework for
   the host language (JDBC `PreparedStatement`, `ProcessBuilder`
   list-form, DOM `textContent`, LDAP `LdapName`/`Filter` builders,
   `XPathExpression` variables, etc.).
4. **Soundness-checkable.** The post-patch claim "no attacker-controlled
   input can be lexed as interpreter syntax" can be expressed as a
   structural invariant over the rewritten host AST.

Memory-safety bugs, logic bugs, races, and crypto-misuse defects fail
principle 1 and are therefore **out of scope**, no exceptions.

## 2. In-scope CWE catalog

| CWE | Title                                           | Interpreter        | MVP? | Phase target | Canonical safe API (Java / Python / JS)                                          |
|-----|-------------------------------------------------|--------------------|------|--------------|----------------------------------------------------------------------------------|
| 89  | SQL Injection                                   | SQL (ANSI + dialects) | YES  | Phase 2     | `PreparedStatement.set*` / DB-API params (`%s`, `?`) / `mysql2` placeholders     |
| 78  | OS Command Injection                            | POSIX shell / cmd  | —    | Phase 4     | `ProcessBuilder(List<String>)` / `subprocess.run([...], shell=False)` / `execFile` |
| 79  | XSS (reflected & stored)                        | HTML + DOM         | —    | Phase 4     | `Element.textContent` / DOM `createElement` + `setAttribute` / template autoescape  |
| 90  | LDAP Injection                                  | LDAP filter        | —    | Phase 4     | `javax.naming.ldap.LdapName` + parameterized filter / `ldap3` Reader API         |
| 643 | XPath Injection                                 | XPath              | —    | Phase 4     | `XPathExpression` with `XPathVariableResolver` / `lxml` `xpath(..., var=val)`    |
| 1336| Server-Side Template Injection (string-only path)| Jinja2 / Velocity | —    | Phase 4     | Pre-compiled templates + data-binding, never `Template(user_input)`              |
| 22  | Path Traversal                                  | Filesystem path resolver | —  | Phase 4     | `Path.resolve().normalize()` + allow-list root containment                       |

## 3. Stretch (Phase 7)

| CWE | Title                                         | Note                                                                 |
|-----|-----------------------------------------------|----------------------------------------------------------------------|
| 502 | Deserialization of Untrusted Data             | Requires extended IAM for object graphs; explicitly Phase 7.        |
| 94  | Code Injection (eval / Function ctor)         | Often subsumes other CWEs; needs sub-interpreter dispatch.          |
| 917 | Expression Language Injection (SpEL/OGNL)     | Variant of 1336 with richer expression grammar.                     |
| 611 | XXE                                           | Mostly configuration-fix; lightweight binder track.                  |

## 4. Out of scope (explicit)

CWE-119/120/121/122 (memory safety), CWE-416 (UAF), CWE-362/367
(concurrency), CWE-327/328/329/330 (crypto-misuse), CWE-352 (CSRF),
CWE-918 (SSRF — network-layer policy, not interpreter syntax),
CWE-287/284/863 (authn/authz logic), CWE-200 (info exposure logic),
CWE-770 (resource exhaustion), CWE-400 (DoS).

These fail one or more of principles 1–4. The thesis is explicit that
IR-SAM **does not** claim to fix them.

## 5. Per-CWE canonical sink tables

The actual sink tables (one row = one library API + tainted-arg index)
live alongside the binders in
`binders/<interpreter>_<framework>.yaml` and are versioned per
release. Sink tables are **data, not code**, to keep the binder
catalog auditable.

## 6. Acceptance criteria for adding a CWE

Before adding a CWE to this list:

1. ≥ 30 CVEs in CVEfixes/BigVul matching the CWE with extractable
   pre/post patches.
2. ≥ 1 safe-API path documented for each in-scope (language,
   framework) pair.
3. A draft binder catalog covering ≥ 80 % of the observed surface
   patterns in step 1.
4. Supervisor approval and an updated versioned amendment to this
   document.
