# Security Hotspot Navigator

Local review guide for Node.js, Java, and Spring Boot. It runs on your machine and binds to localhost only.

This tool identifies code that deserves security review. A hotspot is not necessarily a vulnerability.

## Installation

Install Node.js 18 or newer. There are no packages to install.

## Startup

From this directory:

```bash
node server.js
```

Or pass a repository path to prefill Active mode. Nothing is scanned until you click Scan.

```bash
node server.js --repo "C:\code\interview-repo"
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000).

Use `--port` to change the port. The server listens on `127.0.0.1` only.

## Modes

**Passive** is the default. It does not read a repository. Pick a language family and work the 16-step checklist. Each step has keywords and a regex you can paste into Visual Studio Code Find in Files or Notepad++ Find in Files, with regular expression mode turned on. The editor shows line numbers and jumps to the match. Each regex also has a `ripgrep` command.

Spring / Spring Boot review includes the Java searches, Spring Boot patterns, and classic Spring Framework patterns such as antMatchers, form binding, and SpEL.

**Active** reads a folder you choose and runs those same regular expressions. It lists file, line number, a short snippet, why the line deserves a look, and what to verify. It does not lint, compile, build an AST, modify files, or rewrite the repository.

## Supported languages

- Node.js, JavaScript, and TypeScript
- Java
- Spring Framework and Spring Boot, including Spring MVC and Spring Security

## Hotspot categories

External entry points, authentication, authorization / IDOR / BOLA, SQL injection, NoSQL injection, command injection, XSS, path traversal, file upload, SSRF, XXE, deserialization, secrets, cryptography, password handling, session / cookies, CORS, CSRF, open redirect, mass assignment, logging / sensitive data, and dependency / configuration.

## Source and sink heuristic

Active mode marks a **source** (request data, object ids, request binding) and a **sink** (SQL, commands, files, outbound HTTP, HTML writes, deserialization, and similar).

- **High** confidence: a source and a sink are within 40 lines in the same file.
- **Medium**: a sink exists and some source exists elsewhere in that file.
- **Low**: a sensitive API is present, and the match does not show that it is exploitable.

Forty lines is a proximity hint, not data flow. A later AST pass can replace `scanner/sourceSink.js` without changing the page.

Top hotspots shows at most 20 matches and at most 4 from any single category.

## False positives

Expect them. `prepareStatement`, constant redirects, public `permitAll` on a login path, and checksum hashes are common benign matches. The page says what to verify and what is often harmless. Do not treat a missing `@PreAuthorize` as proof that authorization is absent. The check may live in a filter, a service, or a query.

## What the scan skips

`node_modules`, `target`, `build`, `dist`, `.git`, generated paths, minified JavaScript, and very long lines. The scanner never writes into the repository you point it at.

## Sample code

`test-fixtures/` contains deliberately insecure Node and Java/Spring examples. They are not part of the running server. Try:

```bash
node server.js --repo test-fixtures
```

Check the fixtures from the command line with:

```bash
node scripts/check-fixtures.js
```

## Limitations

This is a line-oriented regex review aid. It does not understand types, call graphs, or frameworks beyond the patterns in `library/catalog.js`. A match is a place to read, not a confirmed vulnerability. There is no CVSS score.
