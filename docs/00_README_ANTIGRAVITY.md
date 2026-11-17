# SentinelRAG — Antigravity Project Pack

## Purpose
This pack is the source of truth for building **SentinelRAG**, a secure Retrieval-Augmented Generation (RAG) application with a dedicated attack simulation lab.

Feed these documents to Antigravity together. Ask it to read all documents before generating code, identify conflicts, and implement the project in phases. Do not ask it to generate the entire application in one step.

## Documents
1. `01_PRD.md` — product vision, users, scope, features, acceptance criteria and roadmap.
2. `02_SRS.md` — detailed functional and non-functional requirements.
3. `03_SYSTEM_ARCHITECTURE.md` — components, data flows, APIs, deployment and implementation boundaries.
4. `04_SECURITY_SPECIFICATION.md` — threat model, security controls, trust boundaries and security requirements.
5. `05_DATABASE_SPECIFICATION.md` — MongoDB collections, ChromaDB metadata, indexes and retention.
6. `06_TESTING_STRATEGY.md` — test plan, attack cases, evaluation metrics and release gates.
7. `07_DESIGN_SYSTEM.md` — visual language, layout, components, states and accessibility.

All seven documents are retained because each serves a different engineering purpose. PRD defines *what and why*; SRS defines *what the software must do*; architecture defines *how components work together*; security defines *how the system is protected*; database defines *how data is stored*; testing defines *how correctness and security are verified*; design system defines *how the UI should look and behave*.

## Recommended implementation sequence
- Phase 0: repository setup, environment configuration, linting, CI and architecture skeleton.
- Phase 1: authentication, user isolation, document upload and document management.
- Phase 2: PDF extraction, chunking, embeddings, ChromaDB indexing and grounded Q&A.
- Phase 3: document screening, prompt-injection classification, trust labels and quarantine.
- Phase 4: secure retrieval, LLM gateway, output validation and audit logging.
- Phase 5: attack simulator lab, test runner, results and baseline/protected comparison.
- Phase 6: dashboard, reports, accessibility, hardening and deployment.

## Instructions for Antigravity
- Treat these documents as requirements, not as permission to invent additional features.
- Build a working vertical slice before expanding functionality.
- Use a modular monolith initially. Do not introduce microservices unless a measured need arises.
- Keep secrets in environment variables or a secret manager. Never commit `.env`.
- Never trust a `user_id`, document ID, role, or permission supplied by the browser without verifying it server-side.
- Never allow the LLM to construct database queries or choose tenant filters.
- Keep retrieved document text untrusted. It is evidence, not executable instruction.
- Do not claim that prompt injection can be eliminated. Implement defense-in-depth and report measured test results.
- Use synthetic secrets and isolated test fixtures in attack simulations. Do not test against real third-party systems.
- All security decisions and attack outcomes must be based on actual execution evidence. Do not hardcode dashboard metrics or simulated success states in production UI.
- If a requirement is ambiguous, document the assumption and choose the safest minimal implementation.
- Before each phase, propose a small task plan; after it, run tests and summarize changed files, decisions, and remaining risks.

## Initial project defaults
- Frontend: React + TypeScript + Vite + Tailwind CSS.
- Backend: Python + FastAPI + Pydantic.
- Primary LLM: Gemini API behind a provider adapter.
- Embeddings: sentence-transformers, initially `all-MiniLM-L6-v2`.
- Vector store: ChromaDB.
- Application database: MongoDB.
- PDF extraction: PyMuPDF.
- Prompt-injection classifier: Meta Prompt Guard 2, deployed only where runtime and licensing constraints are satisfied; classifier is one signal, not a security boundary.
- Authentication: short-lived access JWT plus refresh strategy, secure password hashing, server-side authorization.
- Testing: Pytest, API integration tests, frontend tests and adversarial regression suite.

## Definition of done
A feature is complete only when it has:
1. Implementation consistent with the documents.
2. Input validation and authorization where relevant.
3. Automated tests.
4. Error and empty states.
5. Audit events for security-relevant actions.
6. Updated documentation and no exposed secrets.
