# SentinelRAG — Product Requirements Document (PRD)

**Version:** 1.0  
**Status:** Baseline for implementation  
**Product:** SentinelRAG — Secure Retrieval-Augmented Generation Agent

## 1. Product vision
SentinelRAG is a multi-user document intelligence application that lets users upload documents, ask natural-language questions, and receive answers grounded in their own authorized content. It adds security controls across document ingestion, retrieval, generation and response handling, plus an attack simulation lab to evaluate defenses against prompt injection and related RAG threats.

**Product promise:** useful answers from private knowledge sources, with visible and testable security controls.

## 2. Problem statement
Typical document-chat applications can treat retrieved text as instructions, may fail to enforce document ownership consistently, and often provide little visibility into attacks or security failures. SentinelRAG addresses these risks through defense-in-depth, explicit trust boundaries, tenant isolation, auditability and repeatable adversarial testing.

## 3. Goals
- Allow authenticated users to upload and manage PDF documents.
- Answer questions using only documents the user is authorized to access.
- Provide source citations that map answers to document/page/chunk references.
- Detect and safely handle suspicious document content and prompt-injection attempts.
- Prevent cross-user retrieval and unauthorized actions through backend-enforced controls.
- Validate model outputs before displaying them.
- Provide a dedicated lab for running safe, repeatable security test cases.
- Measure security outcomes and false positives using real test executions.

## 4. Non-goals for initial release
- A general-purpose autonomous agent with arbitrary tool or shell access.
- Sending emails, making purchases, executing code or taking external actions.
- Training or fine-tuning a foundation model.
- Guaranteed detection or prevention of every prompt-injection attack.
- OCR for scanned/image-only PDFs in MVP.
- Public sharing of documents or cross-tenant collaboration.
- Enterprise SSO, billing, multi-region deployment or formal compliance certification.

## 5. Target users
1. **Individual knowledge worker/student:** uploads personal documents and asks questions.
2. **Security-conscious user/tester:** inspects scan results and runs attack scenarios.
3. **Platform administrator:** reviews operational/security events and manages abuse or incidents.

MVP may expose only user and administrator roles. Avoid adding complex role hierarchies until required.

## 6. Core user journeys
### 6.1 Sign up and sign in
A user registers, verifies credentials as configured, signs in and receives a session. Every protected API request is authenticated. The server derives the user identity from the verified token, never from a browser-supplied owner ID.

### 6.2 Upload and index a document
The user uploads a PDF. The backend validates size/type, stores it safely, extracts text, scans for suspicious patterns, classifies risk, and either indexes it or quarantines it according to policy. The UI shows processing status and scan findings.

### 6.3 Ask a question
The user asks a question. The backend authenticates the user, retrieves only that user's eligible chunks, constructs a prompt with explicit untrusted-context boundaries, calls the LLM, validates the answer and citations, then returns a grounded response.

### 6.4 Inspect security center
The user views their own document scan statuses, security events and relevant metrics. Admin-only global views require explicit authorization.

### 6.5 Run an attack simulation
The user selects a predefined test or creates a custom test payload, chooses a test document/fixture and runs it against an isolated test configuration. The application records the test input, execution path, observed result, expected result and verdict.

## 7. Product modules and requirements
### A. Authentication and account
- Registration, login, logout and session refresh.
- Passwords stored only as secure salted hashes.
- JWT validation and server-side role/ownership checks.
- Rate limiting on authentication endpoints.
- Account data must not be exposed to other users.

### B. Document management
- Upload PDF files only in MVP.
- Validate MIME type, extension, file signature and size.
- Generate server-side IDs and safe storage names.
- Show status: `uploaded`, `processing`, `indexed`, `quarantined`, `failed`, `deleting`, `deleted`.
- Allow owner to view metadata and delete documents.
- Deletion must remove associated vector chunks and stored files, with auditable outcome.

### C. RAG assistant
- Natural-language question input.
- Retrieval scoped to authenticated user's indexed/approved documents.
- Grounded answers with citations to document title and page number when available.
- If evidence is insufficient, state that the documents do not contain enough information.
- Do not fabricate citations or present unsupported claims as sourced.
- Conversation history is private to its owner.

### D. Ingestion security
- Detect suspicious instruction-like patterns and hidden/obfuscated content where feasible.
- Run a prompt-injection classifier as a risk signal.
- Apply configurable policy: allow, flag for review, or quarantine.
- Preserve original uploaded file for authorized audit/review subject to retention policy.
- Do not silently rewrite source documents.

### E. Generation and output security
- Treat retrieved content as untrusted data.
- Keep system instructions separate from retrieved context.
- Do not expose secrets, internal prompts, credentials or other users' data.
- Validate structured model output using schemas.
- Sanitize rendered content and reject unsafe HTML.
- Links are inert by default; if links are rendered, validate scheme and apply safe display behavior.

### F. Attack Simulator Lab
- Predefined scenarios: direct prompt injection, indirect prompt injection, secret extraction using synthetic canaries, system-prompt extraction attempts, malicious URL output, multilingual injection, cross-user access and unauthorized tool/action attempts.
- Custom test cases with category, payload, fixture, expected behavior and severity.
- Run one test, a category suite or a full suite.
- Execute against an isolated test tenant/environment and synthetic data.
- Capture stage-by-stage events and final verdict.
- Support baseline versus protected configuration comparison.
- Show attack success rate, defense/block rate, false-positive rate and latency.
- Export test results as CSV initially; PDF report may follow.
- Never run arbitrary attacks against external services or real customer data.

### G. Security center and audit
- Show document scan counts and statuses.
- Show security events visible to the current user; global events are admin-only.
- Record actor, action, target, timestamp, outcome and correlation ID.
- Do not log passwords, API keys, full access tokens or unnecessary document contents.

## 8. MVP acceptance criteria
- A user can register, log in and upload a valid PDF.
- Invalid or oversized files are rejected safely.
- A user can ask a question and receive a grounded answer with valid citations.
- A user cannot retrieve another user's documents by changing IDs or request parameters.
- Suspicious documents are flagged or quarantined according to policy.
- Retrieved text is explicitly treated as untrusted context.
- Output validation runs before a response is returned.
- Attack tests execute against a test instance and produce evidence-based results.
- Dashboard figures are computed from stored test/event records, not hardcoded.
- Tests cover normal questions, malicious inputs, tenant isolation and failure cases.

## 9. Success metrics
Track these from actual runs:
- Retrieval relevance (human-reviewed sample or benchmark).
- Citation correctness.
- Answer groundedness / unsupported answer rate.
- Attack success rate (ASR).
- Attack detection rate and false-positive rate.
- Cross-tenant access test pass rate.
- Median and p95 response latency.
- Document ingestion failure rate.

Do not claim a metric without stating its test dataset, sample size and evaluation method.

## 10. Roadmap
1. Foundation: auth, document upload, metadata and ownership.
2. RAG: parsing, chunking, embeddings, vector retrieval, grounded Q&A.
3. Security: ingestion scanner, classifier, trust labels, authorization and output validation.
4. Attack lab: scenario library, runner, verdict engine and evidence logs.
5. Analytics: security center, comparisons and export.
6. Hardening: rate limits, deletion lifecycle, deployment, monitoring and documentation.

## 11. Product principles
- Secure by default; least privilege.
- User data isolation is enforced by backend code.
- Retrieved content is evidence, never authority.
- Fail closed for authorization and sensitive actions.
- Explain refusals and security decisions without exposing sensitive internals.
- Prefer measurable defenses over claims of perfect security.
