# SentinelRAG — Design System

**Version:** 1.0  
**Product character:** trustworthy, technical, calm, precise and security-focused.

## 1. Design direction
Create a polished cybersecurity SaaS dashboard. The interface should feel like a serious AI security product, not a gaming dashboard or a generic chatbot template.

### Visual principles
- Dark-first theme with a high-quality light theme optional later.
- Deep navy/charcoal surfaces, restrained cyan/blue accent and clear semantic status colors.
- Use color to communicate state, not as decoration.
- Dense information should remain readable and scannable.
- Avoid excessive gradients, glowing borders, glassmorphism and animated backgrounds.
- Use consistent spacing, typography and component states.
- Do not use red for ordinary branding; reserve it for danger and critical findings.

## 2. Brand
- Name: **SentinelRAG**
- Descriptor: Secure Retrieval-Augmented Generation Agent
- Primary tagline: **Intelligence. Protected.**
- Supporting line: **Secure Retrieval. Trusted Generation.**
- Logo direction: a minimal shield/guardian mark combined with a subtle neural-network or document motif. Avoid overly complex robot mascots.

## 3. Color tokens
Suggested initial tokens (adjust after contrast testing):
```css
:root {
  --bg: #0B1220;
  --surface: #111C2E;
  --surface-raised: #17243A;
  --border: #26364D;
  --text-primary: #E8EEF7;
  --text-secondary: #9AAAC0;
  --accent: #43B9E8;
  --accent-hover: #2EA5D5;
  --success: #27B47E;
  --warning: #E6A23C;
  --danger: #E45B65;
  --info: #6D91F0;
}
```
Use semantic tokens in components; do not hardcode colors repeatedly. Verify WCAG AA contrast for text and controls.

## 4. Typography
- Primary font: Inter or a comparable modern sans-serif.
- Monospace: JetBrains Mono or system monospace for IDs, code, payloads and logs.
- Page title: 24–30 px, semibold.
- Section title: 16–20 px, semibold.
- Body: 14–16 px.
- Metadata: 12–13 px.
- Use tabular numerals for metrics and timestamps.

## 5. Layout and navigation
Desktop shell:
- Left sidebar: logo, Dashboard, Documents, AI Assistant, Security Center, Attack Simulator, Settings.
- Top bar: page title/breadcrumb, environment indicator, notifications, user menu.
- Main content: responsive grid with consistent 24 px page gutters.
- Keep the active environment visible, especially in Attack Simulator.

Mobile:
- Collapse sidebar into accessible navigation drawer.
- Stack metric cards and tables.
- Keep primary actions reachable.
- Avoid horizontal scrolling for essential workflows.

## 6. Core screens
### 6.1 Dashboard
- Welcome/overview header.
- Metric cards: documents, indexed, quarantined, recent security events.
- Recent activity list.
- Quick actions: upload document, open assistant, run security tests.
- Metrics must be API-driven, not hardcoded.

### 6.2 Documents
- Upload dropzone with accepted type/size guidance.
- Table/list with filename, upload date, status, pages, risk level and actions.
- Status chips: Uploaded, Processing, Indexed, Review, Quarantined, Failed.
- Detail drawer/page with scan findings and source metadata.
- Confirm destructive deletion.

### 6.3 AI Assistant
- Conversation layout with readable message bubbles.
- Composer with send, disabled/loading state and character limit.
- Source citations displayed as compact expandable references (document title, page and short excerpt).
- Clearly indicate when evidence is insufficient.
- Provide feedback/report action without suggesting answers are guaranteed.
- Do not expose raw internal prompts or hidden chain-of-thought.

### 6.4 Security Center
- Overview metrics from actual events.
- Event table with timestamp, severity, category, resource and decision.
- Filters by date, severity and event type.
- Event detail panel with safe explanation, detector and correlation ID.
- User sees only own events; administrator views require role authorization.

### 6.5 Attack Simulator Lab
Use four main tabs:
1. **Scenarios:** predefined and custom tests, categories, severity, expected behavior.
2. **Run & Monitor:** selected suite, explicit `ISOLATED TEST ENVIRONMENT` banner, progress, stage events and cancellation where safe.
3. **Results & Compare:** verdicts, evidence, baseline/protected comparison, filters.
4. **Reports:** export CSV; PDF can be added later.

Every lab screen must visibly communicate that it runs in a test environment. Never present sample metrics as live results. Use an empty state before any test has run.

## 7. Component library
Build reusable components:
- `AppShell`, `Sidebar`, `Topbar`, `PageHeader`
- `Button` (primary, secondary, danger, ghost)
- `Card`, `MetricCard`, `StatTrend`
- `StatusBadge`, `SeverityBadge`
- `DataTable`, `FilterBar`, `SearchInput`
- `FileDropzone`, `DocumentRow`, `DocumentStatus`
- `ChatMessage`, `ChatComposer`, `CitationCard`
- `SecurityEventRow`, `EventDetail`
- `ScenarioCard`, `AttackPayloadEditor`, `RunProgress`
- `VerdictBadge`, `StageTimeline`, `ComparisonChart`
- `ConfirmDialog`, `Toast`, `Tooltip`, `Skeleton`, `EmptyState`, `ErrorState`

Each component needs hover, focus-visible, disabled, loading and error states where applicable.

## 8. Interaction and status language
Use clear, non-alarmist language:
- `Blocked`: a defined unsafe outcome was prevented and verified.
- `Detected`: a detector raised a signal; not necessarily blocked.
- `Quarantined`: excluded from normal retrieval pending review.
- `Attack succeeded`: an exploit condition was observed.
- `Inconclusive`: insufficient evidence to decide.
- `Error`: test execution failed.

Never label a test “secure” solely because a classifier returned benign.

## 9. Accessibility and usability
- Keyboard navigation for all controls.
- Visible focus indicators.
- Semantic headings and labels.
- Accessible names for icon-only buttons.
- Do not communicate status through color alone; include text/icon.
- Respect reduced-motion preferences.
- Charts need text summaries or accessible data tables.
- Provide confirmation for destructive actions.
- Use clear validation messages near fields.

## 10. Responsive behavior
- Desktop: full sidebar and multi-column dashboards.
- Tablet: compact sidebar and two-column cards.
- Mobile: single-column cards, stacked filters and scrollable data tables with accessible alternatives.
- Chat and attack payload editors must remain usable on narrow screens.

## 11. Content and microcopy
Prefer concise, factual labels:
- “Scan document”
- “Quarantine document”
- “Run selected tests”
- “View evidence”
- “Compare configurations”
- “No security tests have been run yet”
- “This document is excluded from retrieval while under review”

Avoid unsupported claims such as “100% protected”, “unhackable” or “zero risk”.

## 12. Motion
Use subtle transitions (150–200 ms) for navigation, drawers and state changes. No decorative looping animations. Respect reduced-motion settings.

## 13. Design acceptance criteria
- All main screens use shared tokens and reusable components.
- Layout works at desktop, tablet and mobile widths.
- Empty/loading/error/success states exist.
- Status is understandable without color.
- Attack lab visibly identifies the isolated test environment.
- Dashboard numbers are real API data or explicitly labeled demo data.
- Keyboard and contrast checks are completed before release.
