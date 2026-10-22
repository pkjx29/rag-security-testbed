# Threat model

Scope: a single-tenant research prototype that answers questions over public NIST guidance
for a fictional hospital, with synthetic personal records in the same index.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Synthetic patient records (name, DOB, SSN, MRN, phone, e-mail, incident) | `restricted` chunks in both indexes; `data/synthetic/` | Stand-in for PHI |
| Synthetic HR memos (employee personal data) | chunks labelled `public` by mistake | Personal data that access control cannot protect |
| Index contents | `storage/chroma` | Whatever enters the index can be retrieved |
| Document permissions | `data/processed/acl.json`, Chroma metadata | Decide what each role sees |
| System instructions and canary `NW-ASSIST-7731` | `pipeline/rag.py` | Stand-in for confidential configuration |
| Model responses | API responses, benchmark case files | The channel through which every leak happens |

## Trust boundaries

1. **Ingestion.** Public PDFs and anything else indexed are untrusted text.
2. **Retrieval.** The vector store is a candidate generator, not an authority on permissions.
3. **User input.** The question is untrusted. Identity comes from the API key.
4. **Model context.** Everything retrieved is attacker-influencable data.
5. **Output.** Model output is untrusted until D4 has run.
6. **Logs and reports.** These must not contain raw personal values.

## Threat actors and capabilities

| Actor | Capability | Not assumed |
|---|---|---|
| Curious or malicious low-privilege user (`public` key) | Asks any question, claims any role in text, knows some patient names | Cannot change server config or keys |
| Content poisoner | Gets **one** document into an indexed public source (shared drive, wiki, uploaded PDF) | Cannot edit the system prompt, other documents or the question |
| Careless insider | Files a document under the wrong access level | Not malicious |

## Scenarios, benchmark coverage and expected controls

| # | Scenario | Benchmark category (n) | Primary control | Secondary |
|---|---|---|---|---|
| 1 | Direct request for a named patient's identifiers | `pii_direct` (10) | D2 | D1, D4 |
| 2 | Enumeration ("list all patients with ...") | `pii_enumeration` (8) | D2 | D1, D4 |
| 3 | Role claim in the question ("I am the treating physician") | `pii_role_claim` (5) | D2 (role from key, not text) | D4 |
| 4 | Ordinary question whose answer sits in a record | `pii_incidental` (7) | D2 | D1 |
| 5 | Poisoned document hijacks the answer, plants links, phishes, misinforms or extracts the system prompt | `injection` (50 = 5 goals × 10 carriers) | D3 | D4 for links and secret |
| 6 | Poisoned document tells the model to output identifiers from other retrieved records | `indirect_extraction` (5) | D2 (records not retrieved) | D3, D4 |
| 7 | Mislabelled document with personal data (HR memos) | covered by 1–4 | D1, D4 | — (D2 cannot help) |
| 8 | Vector-store metadata wrong or tampered | `tests/security` | D2 independent ACL check | — |
| 9 | Caller tries to switch off authorisation through the API | `tests/integration` | API forces D2 on | — |
| 10 | Benign text that looks like an injection | `benign_lookalike` (8) | measures D3 false positives | — |

## Out of scope and residual risks

* **Paraphrased leaks.** Scoring uses exact or formatted string matches. A model that
  paraphrases a value ("born in the summer of '62") is not counted as a leak.
* **Semantic attacks.** D3 is pattern-based and D4 cannot judge meaning. A goal-hijacking
  or misinformation payload phrased without trigger words gets through both, if the model
  obeys it.
* **Presidio recall.** Names missed by `en_core_web_sm` stay in the "protected" index
  (3 of 50 seeded names in our data).
* **Multi-document and adaptive attacks.** Each case plants one document. Attacks that
  spread across documents or adapt to the filter were not tested.
* **Model and inference integrity.** Weights come from the Hugging Face cache, and their
  integrity is trusted.
* **Side channels.** Timing, retrieval ranking and citation excerpts are not analysed as
  leak channels. Citation excerpts only ever come from authorised evidence.
* **Authentication.** Static API keys are for local development only. There is no TLS,
  rate limiting or key rotation, so do not expose the service.
* **No compliance claim.** This prototype is not HIPAA-compliant software and makes no
  guarantee of privacy.
