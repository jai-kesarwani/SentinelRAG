# SentinelRAG — Database Specification

**Version:** 1.0

## 1. Storage responsibilities
- **MongoDB:** users, documents, conversations, messages, security events, attack scenarios, test runs and approvals if introduced later.
- **ChromaDB:** chunk embeddings and retrieval metadata.
- **File/object storage:** original uploaded files and optional generated exports. Do not store binary PDFs directly in MongoDB for the initial design.

## 2. General rules
- Use server-generated UUID/ULID/ObjectId identifiers.
- Store timestamps in UTC.
- Store ownership fields on every user-owned record.
- Never accept `owner_id` from client as authority.
- Validate all records through Pydantic/domain models.
- Add indexes for common ownership and time queries.
- Avoid storing secrets or unnecessary extracted document text in operational logs.
- Keep vector IDs deterministic or persist the mapping so deletion can reliably remove chunks.

## 3. MongoDB collections

### 3.1 `users`
```json
{
  "_id": "user_id",
  "email": "person@example.test",
  "password_hash": "argon2id-or-bcrypt-hash",
  "display_name": "Example User",
  "role": "user",
  "status": "active",
  "created_at": "UTC datetime",
  "updated_at": "UTC datetime",
  "last_login_at": "UTC datetime"
}
```
Indexes:
- Unique normalized `email`.
- `status`.

Do not store plaintext passwords or API keys.

### 3.2 `documents`
```json
{
  "_id": "document_id",
  "owner_id": "user_id",
  "original_filename": "policy.pdf",
  "storage_key": "random-private-key",
  "mime_type": "application/pdf",
  "file_size_bytes": 123456,
  "sha256": "file-content-hash",
  "status": "uploaded",
  "page_count": 12,
  "chunk_count": 42,
  "trust": {
    "status": "review",
    "risk_level": "medium",
    "signals": ["instruction_like_text"],
    "scanner_version": "scanner-version",
    "classifier_version": "model-version",
    "scanned_at": "UTC datetime",
    "policy_decision": "review"
  },
  "created_at": "UTC datetime",
  "updated_at": "UTC datetime",
  "deleted_at": null
}
```
Allowed statuses: `uploaded`, `processing`, `indexed`, `review`, `quarantined`, `failed`, `deleting`, `deleted`.

Indexes:
- `{ owner_id: 1, created_at: -1 }`
- `{ owner_id: 1, status: 1 }`
- `{ sha256: 1, owner_id: 1 }` (deduplication only within owner unless policy states otherwise)

### 3.3 `conversations`
```json
{
  "_id": "conversation_id",
  "owner_id": "user_id",
  "title": "Leave policy questions",
  "created_at": "UTC datetime",
  "updated_at": "UTC datetime"
}
```
Indexes:
- `{ owner_id: 1, updated_at: -1 }`

### 3.4 `messages`
```json
{
  "_id": "message_id",
  "conversation_id": "conversation_id",
  "owner_id": "user_id",
  "role": "user",
  "content": "Question or answer text",
  "citations": [
    {
      "document_id": "document_id",
      "chunk_id": "chunk_id",
      "page_number": 3,
      "excerpt": "Short validated excerpt"
    }
  ],
  "created_at": "UTC datetime",
  "validation_status": "validated"
}
```
Indexes:
- `{ owner_id: 1, conversation_id: 1, created_at: 1 }`
- Ensure conversation ownership is checked before message access.

### 3.5 `security_events`
```json
{
  "_id": "event_id",
  "owner_id": "user_id-or-null",
  "actor_user_id": "user_id-or-null",
  "correlation_id": "request-id",
  "event_type": "document_injection_detected",
  "severity": "high",
  "resource_type": "document",
  "resource_id": "document_id",
  "decision": "quarantined",
  "reason_code": "INJECTION_RISK",
  "detector": {
    "name": "prompt_guard",
    "version": "version"
  },
  "safe_metadata": {},
  "created_at": "UTC datetime"
}
```
Indexes:
- `{ owner_id: 1, created_at: -1 }`
- `{ event_type: 1, created_at: -1 }`
- `{ correlation_id: 1 }`
- Apply retention/TTL only after defining audit retention requirements.

### 3.6 `attack_scenarios`
```json
{
  "_id": "scenario_id",
  "created_by": "user_id-or-system",
  "name": "Indirect injection - fake secret",
  "category": "indirect_prompt_injection",
  "severity": "critical",
  "description": "Synthetic test description",
  "payload": "Test payload using synthetic canary only",
  "fixture_document_id": "test_document_id",
  "expected_behavior": "must_not_disclose_canary",
  "evaluation_rules": ["canary_absent", "no_unauthorized_action"],
  "version": 1,
  "is_system": true,
  "created_at": "UTC datetime",
  "updated_at": "UTC datetime"
}
```
System scenarios are read-only to ordinary users. Custom scenarios must be owner-scoped.

Indexes:
- `{ category: 1, severity: 1 }`
- `{ created_by: 1, updated_at: -1 }`

### 3.7 `attack_runs`
```json
{
  "_id": "run_id",
  "owner_id": "user_id",
  "environment": "isolated_test",
  "mode": "protected",
  "scenario_ids": ["scenario_id"],
  "build_version": "app-version-or-commit",
  "status": "completed",
  "started_at": "UTC datetime",
  "completed_at": "UTC datetime",
  "summary": {
    "total": 1,
    "blocked": 1,
    "detected_not_blocked": 0,
    "succeeded": 0,
    "inconclusive": 0,
    "errors": 0
  }
}
```
Indexes:
- `{ owner_id: 1, started_at: -1 }`
- `{ status: 1, started_at: -1 }`

### 3.8 `attack_results`
```json
{
  "_id": "result_id",
  "run_id": "run_id",
  "owner_id": "user_id",
  "scenario_id": "scenario_id",
  "scenario_version": 1,
  "verdict": "blocked",
  "stage_events": [
    {
      "stage": "document_scan",
      "decision": "quarantined",
      "reason_code": "INJECTION_RISK",
      "latency_ms": 35
    }
  ],
  "output_assessment": {
    "canary_detected": false,
    "unsafe_url_detected": false,
    "unauthorized_source_detected": false,
    "expected_behavior_met": true
  },
  "latency_ms": 120,
  "safe_output_excerpt": "Sanitized excerpt only",
  "created_at": "UTC datetime"
}
```
Indexes:
- `{ owner_id: 1, run_id: 1 }`
- `{ run_id: 1, verdict: 1 }`
- `{ scenario_id: 1, created_at: -1 }`

## 4. ChromaDB collection
Suggested collection: `sentinelrag_chunks` (or per-environment/per-tenant collections if chosen).

Each vector record:
- `id`: unique chunk ID.
- `embedding`: vector generated by configured embedding model.
- `document`: chunk text.
- `metadata`:
  - `owner_id`
  - `document_id`
  - `page_number`
  - `chunk_index`
  - `trust_status`
  - `document_status`
  - `source_filename` (display-only metadata)
  - `embedding_model_version`
  - `created_at`

Only approved/indexed chunks are eligible for retrieval. The backend must enforce owner scope and verify returned metadata; do not rely on vector metadata filters as the sole security control.

## 5. Chunking defaults
Initial tunable defaults:
- Chunk size: approximately 700–1,000 tokens.
- Overlap: approximately 100–150 tokens.
- Preserve page boundaries and source metadata.
- Avoid splitting in the middle of a sentence where practical.
- Record chunker version and embedding model version.
- Benchmark retrieval quality before tuning; these are starting values, not universal optima.

## 6. Deletion and consistency
Document deletion is a multi-step operation:
1. Authorize owner.
2. Mark document `deleting` to prevent retrieval.
3. Remove all vector records associated with document ID and owner ID.
4. Delete original file from private storage.
5. Remove or anonymize derived content according to retention policy.
6. Mark `deleted` and write audit event.
7. If any step fails, retain `deleting` state and retry safely; never re-enable retrieval during partial deletion.

## 7. Retention and privacy
- Define retention periods before production.
- Provide a user data deletion workflow.
- Keep security event retention separate from chat/document retention.
- Redact secrets from logs and test output.
- Use synthetic canaries only in attack lab.
- Restrict admin access to document content and raw payloads.
