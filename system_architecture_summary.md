# GuardianAI CI/CD Security Audit - System Architecture

Welcome to the finalized system architecture report for the **GuardianAI Automated Security Gates** initiative. This document outlines the components, data flows, and security enforcement mechanisms integrated into the developer workflow.

## Overview
GuardianAI acts as a localized Static Application Security Testing (SAST) tool capable of autonomously finding vulnerabilities in your codebase and generating AI-augmented remediation roadmaps. To ensure early detection, we integrated the analyzer directly into the core development lifecycle.

## Architectural Components

> [!NOTE]
> The security scanning process consists of three main foundational engines natively bundled in the repository.

### 1. `scanner.py` (Core AST & REGEX Engine)
- **Purpose:** Parses source code looking for vulnerable patterns without executing the application.
- **Capabilities:** 
  - Parses Python using `ast` traversing to discover Abstract Syntax Tree-based injections (e.g., executing formatted strings straight to DBs).
  - Matches JavaScript (`.js`) vulnerabilities using Regular Expression heuristics—specifically analyzing unparameterized Template Literals injected into `SELECT/UPDATE/INSERT` sequences.
- **Yields:** `Finding` objects populated with severity data, path information, rules breached, and snippets.

### 2. `advisor.py` (Analysis & Aggregation Orchestrator)
- **Purpose:** Orchestrates the system by consuming findings from `scanner.py` and determining operational severity.
- **Capabilities:** 
  - Interacts dynamically with an Ollama-based AI Mentor (or relies on fallback rule-based mapping) to compile an educational `.md` roadmap for the developer outlining the flaws and remediation instructions.
  - Controls the **CI Build Failurer** (the `--ci` flag), mapping rules to severity scores. If the highest discovered severity exceeds `7`, the analyzer triggers a soft crash `sys.exit(1)`, halting continuous integration or local commit procedures.

### 3. Pipeline Gateways
We've constructed strict automated barricades preventing volatile code from progressing to production.

#### Local Gatekeeper (`.git/hooks/pre-commit`)
- **Type:** Developer Local Check
- **Process:** Executes locally whenever a developer writes `git commit`. 
- **Action:** Triggers `python scanner.py .`. If vulnerabilities exist (`$? -ne 0`), it halts the commit natively via Bash and executes the `advisor` to dump an actionable Markdown file for the developer.

#### CI/CD Gateway (`guardian_security_audit.yml`)
- **Type:** Remote Verification Check
- **Process:** Integrated into GitHub Actions traversing every `push` or `pull_request` to the `main/master` branches.
- **Action:** Evaluates `python advisor.py . --ci`. The `--ci` implementation dumps the issues directly to the Actions Console logs, aborts the pipeline if thresholds are exceeded, and permanently archives building `reports/*.md` artifacts to the GitHub Workflow Dashboard tracing historic weaknesses.

---

> [!TIP]
> **Extensibility**
> GuardianAI's analyzer architecture is decoupled, allowing seamless integration of parsers for additional languages (Java, Go, Ruby) by merely expanding `scanner.py`'s file iteration strategy and mapping rule definitions in `advisor.py`.

## Security Rule Mapping Summary

| Rule Definition | Vulnerability | Severity Trigger | Gateway Block |
| -- | -- | -- | -- |
| `SQLI.AST.TAINTED_NONPARAM` | Tainted Python String Execution | **9** | **Blocked** |
| `SQLI.JS.TEMPLATE_INJECTION` | Unsafe JS Template Literals | **9** | **Blocked** |
| `SQLI.AST.NONPARAM` | Nonparameterized Execution | **8** | **Blocked** |
| `SQLI.AST.FSTRING` | F-String formatted execution | **6** | Warned |

---

> [!SUCCESS]
> **Final Conclusion:**
> The integrations effectively shift-left security analysis. By blocking unparameterized javascript and vulnerable python payloads earlier in the SDLC pipeline, GuardianAI eliminates downstream runtime compromises and prevents toxic payloads from entering upstream code repositories.
