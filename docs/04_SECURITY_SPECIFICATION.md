# SentinelRAG — Security Specification

**Version:** 1.0  
**Security posture:** Defense-in-depth; no claim of perfect prompt-injection prevention.

## 1. Security objectives
- Preserve confidentiality between users.
- Preserve integrity of system instructions, application policy and stored records.
- Ensure availability through resource limits and abuse controls.
- Prevent untrusted documents/prompts from causing unauthorized actions.
- Make security decisions observable and testable.

## 2. Threat model
### Assets
- User credentials and sessions.
- Uploaded documents and extracted text.
- Embeddings and vector metadata.
- Conversation history.
- Synthetic canary secrets used in tests.
- Gemini/API credentials and database credentials.
- System prompts, application configuration and audit records.

### Trust boundaries
1. Browser to API.
2. Uploaded file to parser.
3. Extracted content to scanner/indexer.
4. Vector store to prompt builder.
5. Prompt builder to external LLM provider.
6. Model output to frontend.
7. Attack lab to test sandbox.
8. One tenant's data to another tenant's data.

### Threat actors
- Malicious authenticated user.
- Unauthenticated attacker probing APIs.
- User uploading a poisoned document.
- Malicious instructions embedded in otherwise useful content.
- Compromised or misconfigured dependency/provider.
- Accidental developer misconfiguration.

## 3. Principal threats and controls
| Threat | Required controls |
|---|---|
| Direct prompt injection | Input checks, fixed system policy, bounded behavior, no privileged model tools |
| Indirect prompt injection | Document scanning, trust labels, untrusted-context delimiters, retrieval-time checks, output validation |
| Cross-user data leakage | Server-derived identity, owner-scoped queries, object authorization, negative tests |
| Secret extraction | No secrets in prompts, canary tests, output scanning, secret redaction |
| System prompt extraction | Do not treat prompt secrecy as sole defense; keep credentials and sensitive data out of prompts |
| Malicious links/HTML | URL scheme validation, safe rendering, no automatic fetch/navigation |
| Unauthorized tool/action use | No arbitrary tools in MVP; explicit allowlist and backend authorization if added |
| Malformed/hostile PDF | File validation, parser limits, isolated processing, no active content execution |
| DoS/resource exhaustion | Upload limits, page/text limits, timeouts, rate limits, bounded tokens/top-k |
| Prompt Guard evasion | Multiple controls; classifier is advisory and evaluated against test corpus |
| Log leakage | Structured logging, redaction, access restrictions and retention limits |
| API abuse | Authentication, rate limits, validation, CORS and secure deployment |

## 4. Security design requirements

### 4.1 Identity and access
- Authenticate every protected request.
- Use secure password hashing (Argon2id preferred, or bcrypt with appropriate cost).
- Keep access tokens short-lived; define refresh/revocation strategy.
- Use secure, HttpOnly, SameSite cookies where the deployment architecture supports them; otherwise carefully protect bearer tokens against XSS.
- Derive identity and roles from verified server-side session/token claims.
- Check object ownership on every document, conversation, event and lab resource operation.
- Return a generic not-found/unavailable response where revealing resource existence would enable enumeration.
- Apply rate limits and lockout/backoff controls to authentication.

### 4.2 File and parser safety
- Accept only configured file types.
- Validate extension, MIME and magic bytes; do not trust filename or browser MIME alone.
- Set file-size, page-count, extracted-character and processing-time limits.
- Store uploads outside the web root using random names.
- Do not execute embedded content or follow external references from PDFs.
- Run parser in a restricted process/container where practical.
- Clean temporary files and handle partial failures.
- Consider malware scanning in production deployment.

### 4.3 Document trust and prompt injection
- Treat every uploaded document as untrusted, including documents from the owner.
- Scan both extracted text and relevant metadata.
- Detect suspicious patterns and obfuscation signals; preserve original content.
- Use Prompt Guard 2 as an additional classifier where feasible.
- Record classifier/model version, score/label and policy decision.
- Do not make a single classifier score the only gate.
- Quarantined/review documents must not enter ordinary retrieval.
- Recheck trust status at retrieval time.
- Retrieved passages must be passed as data, never as privileged instructions.
- The system prompt is not a security boundary; enforce policy in application code.

### 4.4 RAG isolation and retrieval
- Retrieval filters are created by trusted backend code.
- Never accept arbitrary ChromaDB filters from clients or the LLM.
- Validate owner/document/status metadata on every returned chunk.
- Limit top-k, chunk size, context length and number of documents.
- Prevent retrieval from quarantined, deleted or non-indexed documents.
- Do not use similarity score alone as authorization.

### 4.5 LLM and provider boundary
- Gemini API key is backend-only.
- Use timeouts, bounded retries and output token limits.
- Do not send unnecessary personal/sensitive data to the provider.
- Document the provider's data handling settings and retention terms before production use.
- Never provide model with database credentials, filesystem access, shell access or unrestricted network access.
- Model output is untrusted and must be validated.
- Do not rely on model refusal behavior as the only defense.

### 4.6 Output security
- Validate output against a typed schema.
- Validate citation IDs against retrieved chunks.
- Scan for synthetic canary secrets and configured sensitive patterns.
- Escape/sanitize rendered markup; prefer plain text or a safe Markdown renderer.
- Reject unsafe URL schemes; do not automatically fetch URLs or images.
- Do not render model-generated HTML directly.
- If a response fails validation, return a safe fallback and record the event.

### 4.7 Attack lab isolation
- Use synthetic users, documents, canary values and test data.
- Execute only against a local/test instance or isolated test tenant.
- Baseline mode may disable selected defenses but must not disable authentication, tenant isolation, sandbox restrictions or audit logging.
- Do not support arbitrary external target URLs.
- Do not run destructive payloads against production records.
- Apply per-run timeouts, test-count limits and payload-size limits.
- Label test results with environment, build/version, scenario version and configuration.

### 4.8 Human approval
MVP should not include external side-effecting tools. If future versions add actions such as deleting, sharing or sending:
- Define a strict allowlist of actions.
- Backend validates actor, object, parameters and permissions.
- Show the exact action and parameters to the user.
- Require explicit confirmation bound to that action.
- Revalidate authorization at execution time.
- Use idempotency keys and audit records.
- Never let the LLM itself approve or execute a sensitive action.

## 5. Security event schema
Record:
- `event_id`
- `timestamp`
- `correlation_id`
- `actor_user_id` (if known)
- `event_type`
- `severity`
- `resource_type`
- `resource_id`
- `decision`
- `reason_code`
- `detector_name` and version
- `environment`
- safe metadata

Do not store passwords, API keys, full JWTs, refresh tokens or unredacted canary values in logs. Restrict access to raw attack payloads and document excerpts.

## 6. Initial risk register
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Cross-tenant vector retrieval | Medium | Critical | Server-side owner filters, metadata verification, isolation tests |
| Indirect prompt injection bypasses scanner | High | High | Multiple controls, quarantine policy, adversarial tests |
| False-positive quarantine | Medium | Medium | Review state, tune thresholds, measure false positives |
| PDF parser resource exhaustion | Medium | High | File/page/CPU/time limits, isolated parsing |
| Sensitive content sent to model provider | Medium | High | Minimize context, provider review, user disclosure |
| Output contains unsafe markup/link | Medium | High | Schema validation, sanitization, URL allowlist |
| Attack lab affects real data | Low | Critical | Synthetic isolated tenant, hard boundaries, test-only credentials |

## 7. Security release gates
A release must not proceed if:
- Any test can retrieve another user's document or conversation.
- A quarantined/deleted document is retrievable.
- A client can set or override the retrieval owner filter.
- API keys or secrets are present in frontend bundles or logs.
- Upload limits or parser timeouts are absent.
- Attack lab can target production data or arbitrary external hosts.
- Unsafe HTML is rendered without sanitization.
- Security dashboard displays fabricated metrics.

## 8. Limitations
Prompt injection is an evolving class of attack. Pattern matching, classifiers, prompt instructions and output filters can all be bypassed. SentinelRAG should communicate residual risk, measure performance on a versioned test corpus and avoid claims such as “100% prompt-injection proof.”
