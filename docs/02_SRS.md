# SentinelRAG — Software Requirements Specification (SRS)

**Version:** 1.0

## 1. Purpose and scope
This SRS defines observable software behavior and quality requirements for SentinelRAG. It complements the PRD: the PRD describes product goals; this document defines system requirements suitable for implementation and verification.

## 2. Definitions
- **RAG:** Retrieval-Augmented Generation.
- **Chunk:** A segment of extracted document text stored for retrieval.
- **Tenant/owner:** The authenticated user who owns a document or conversation.
- **Untrusted context:** User-supplied or retrieved document content that must not override system policy.
- **Canary secret:** A synthetic test-only secret used to detect leakage.
- **Quarantine:** A state in which a document is retained but excluded from normal retrieval.
- **ASR:** Attack Success Rate.

## 3. External interfaces
### 3.1 User interface
React web application with authenticated pages for dashboard, documents, chat, security center, attack lab and settings.

### 3.2 API interface
JSON REST API over HTTPS. File upload uses multipart form data. API errors use a consistent structure with machine-readable code, safe message and correlation ID.

### 3.3 External services
- Gemini API through a backend-only provider adapter.
- Optional Prompt Guard 2 inference service.
- MongoDB for application records.
- ChromaDB for vector embeddings.
- Optional object/file storage for uploaded originals.

## 4. Functional requirements

### 4.1 Authentication
- `FR-AUTH-01`: The system shall allow a user to register with validated credentials.
- `FR-AUTH-02`: The system shall store password hashes using a modern password hashing algorithm such as Argon2id or bcrypt with safe parameters.
- `FR-AUTH-03`: The system shall authenticate users and issue short-lived access tokens.
- `FR-AUTH-04`: The system shall validate token signature, expiry, issuer/audience where configured, and revocation/session state where applicable.
- `FR-AUTH-05`: The system shall derive user identity and roles from verified server-side claims.
- `FR-AUTH-06`: The system shall rate-limit login and registration attempts.
- `FR-AUTH-07`: The system shall not reveal whether an arbitrary email exists through overly specific login errors.

### 4.2 Document upload and processing
- `FR-DOC-01`: The system shall accept PDF files in MVP.
- `FR-DOC-02`: The system shall validate extension, declared MIME type, file signature and configured maximum size.
- `FR-DOC-03`: The system shall reject malformed, empty, encrypted/unreadable or unsupported files with safe error messages.
- `FR-DOC-04`: The system shall assign a server-generated document ID and owner ID.
- `FR-DOC-05`: The system shall extract text and page boundaries.
- `FR-DOC-06`: The system shall scan extracted content and relevant PDF metadata for suspicious patterns.
- `FR-DOC-07`: The system shall record scanner/classifier version, timestamp, risk signals and policy decision.
- `FR-DOC-08`: The system shall not index quarantined documents for normal user chat.
- `FR-DOC-09`: The system shall chunk approved extracted text and generate embeddings.
- `FR-DOC-10`: Each vector record shall include server-controlled owner ID, document ID, page/source metadata and trust status.
- `FR-DOC-11`: The system shall expose processing status to the owner.
- `FR-DOC-12`: The owner shall be able to request deletion of a document and its derived chunks.

### 4.3 Retrieval and generation
- `FR-RAG-01`: The system shall authenticate every chat request.
- `FR-RAG-02`: The retrieval service shall apply owner/tenant filters derived from verified authentication context.
- `FR-RAG-03`: The model shall not be able to choose or override the owner filter.
- `FR-RAG-04`: The retriever shall return a bounded number of relevant chunks.
- `FR-RAG-05`: The system shall preserve source metadata required for citations.
- `FR-RAG-06`: The prompt shall explicitly identify retrieved text as untrusted reference material.
- `FR-RAG-07`: The system shall instruct the model to answer only from relevant evidence and to report insufficient evidence.
- `FR-RAG-08`: The system shall validate returned citations against the retrieved chunk set.
- `FR-RAG-09`: The system shall validate output schema and sanitize content before display.
- `FR-RAG-10`: The system shall handle provider timeout, rate limit and malformed output without leaking secrets.
- `FR-RAG-11`: The system shall store conversation history with owner ID and enforce ownership on read/delete.

### 4.4 Security controls
- `FR-SEC-01`: The system shall classify suspicious document/prompt content using deterministic rules and an optional ML classifier.
- `FR-SEC-02`: Classifier output shall be treated as a risk signal, not as the sole authorization decision.
- `FR-SEC-03`: The system shall support allow, flag and quarantine policies for ingestion.
- `FR-SEC-04`: The system shall prevent untrusted content from invoking application tools or changing system policy.
- `FR-SEC-05`: The system shall not provide the LLM direct database credentials or unrestricted database access.
- `FR-SEC-06`: The system shall validate URL schemes and reject unsafe schemes such as `javascript:` and `data:` for clickable links.
- `FR-SEC-07`: The system shall detect configured synthetic canary values in generated output and record a leakage event.
- `FR-SEC-08`: The system shall log security-relevant decisions with correlation IDs.
- `FR-SEC-09`: The system shall redact secrets and sensitive tokens from logs.

### 4.5 Attack Simulator Lab
- `FR-LAB-01`: The system shall provide versioned predefined attack test cases.
- `FR-LAB-02`: An authorized user shall be able to create, edit and save custom test cases.
- `FR-LAB-03`: Each test case shall define category, severity, payload/fixture, expected behavior and evaluation rule.
- `FR-LAB-04`: Test execution shall occur in a sandbox/test tenant with synthetic data.
- `FR-LAB-05`: Test execution shall record input, relevant pipeline stages, detector decisions, output assessment and verdict.
- `FR-LAB-06`: The system shall support single, category and full-suite runs.
- `FR-LAB-07`: The system shall distinguish `blocked`, `detected_but_not_blocked`, `attack_succeeded`, `inconclusive` and `error`.
- `FR-LAB-08`: The system shall compare baseline and protected runs using the same test case version and fixtures.
- `FR-LAB-09`: The system shall calculate metrics from persisted executions.
- `FR-LAB-10`: The system shall allow export of test results as CSV.
- `FR-LAB-11`: The system shall prevent test payloads from targeting arbitrary external hosts or production user data.

### 4.6 Security center and administration
- `FR-OBS-01`: A user shall see only their own document and security events unless granted an administrator role.
- `FR-OBS-02`: Administrators shall be able to view platform-level aggregates and security events.
- `FR-OBS-03`: Dashboard counts shall be derived from database records.
- `FR-OBS-04`: Security events shall include timestamp, actor, action, target, result, severity and correlation ID where applicable.

## 5. Non-functional requirements
- `NFR-SEC-01`: All production traffic shall use HTTPS.
- `NFR-SEC-02`: Secrets shall be stored outside source control and never sent to the browser.
- `NFR-SEC-03`: All object-level authorization shall be enforced server-side.
- `NFR-SEC-04`: The system shall apply request size limits, rate limits and safe timeouts.
- `NFR-SEC-05`: File processing shall use resource limits and safe temporary-file handling.
- `NFR-PRIV-01`: The system shall collect only data needed for operation and testing.
- `NFR-REL-01`: External model/vector/database failures shall produce controlled errors and not bypass authorization.
- `NFR-PERF-01`: The application shall record latency for upload, retrieval and generation; performance targets shall be set after baseline measurement.
- `NFR-MAINT-01`: Backend modules shall have clear boundaries and typed interfaces.
- `NFR-TEST-01`: Security-critical logic shall have automated unit and integration tests.
- `NFR-UX-01`: The UI shall provide loading, empty, success, warning and error states.
- `NFR-ACC-01`: Core flows shall be keyboard accessible and use semantic labels and sufficient contrast.

## 6. API requirements (initial contract)
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/documents`
- `GET /api/v1/documents`
- `GET /api/v1/documents/{document_id}`
- `DELETE /api/v1/documents/{document_id}`
- `POST /api/v1/chat/ask`
- `GET /api/v1/conversations`
- `GET /api/v1/conversations/{conversation_id}`
- `GET /api/v1/security/overview`
- `GET /api/v1/security/events`
- `GET /api/v1/lab/scenarios`
- `POST /api/v1/lab/scenarios`
- `POST /api/v1/lab/runs`
- `GET /api/v1/lab/runs/{run_id}`
- `GET /api/v1/lab/runs/{run_id}/results`
- `GET /api/v1/lab/runs/{run_id}/export`

All endpoints except registration/login and explicitly public health checks require authentication. Ownership and role authorization are mandatory.

## 7. Error handling
Use a consistent response envelope, for example:
```json
{
  "error": {
    "code": "DOCUMENT_NOT_ACCESSIBLE",
    "message": "The requested document is unavailable.",
    "correlation_id": "server-generated-id"
  }
}
```
Do not return stack traces, raw provider errors, filesystem paths, secrets or internal prompt content to clients.

## 8. Constraints and assumptions
- Initial release is a modular monolith.
- PDF is the first supported document type.
- Gemini is accessed only from backend.
- Prompt Guard may be hosted locally or as a separately managed inference component; deployment choice must be documented.
- ChromaDB metadata filters are not a substitute for backend authorization. Enforce tenant scoping in the retrieval service and test it.
- Baseline testing may disable selected defenses only in a disposable sandbox with synthetic data.
