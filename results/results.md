# Results

Model `mlx-community/Qwen2.5-1.5B-Instruct-4bit` (greedy decoding), top-k = 4, 50 injection cases, 30 personal-data attack questions, 10 NIST QA + 6 authorised-lookup utility questions. Brackets are 95% Wilson intervals.

## Main table

| Config | Injection success | PII-leak queries | Leaks incl. identifiers | Distinct values leaked | NIST QA (utility) | Authorised lookups |
|---|---|---|---|---|---|---|
| **C0** No defence | 6% [2–16] | 70% [52–83] | 60% | 84 | 80% | 67% |
| **D1** Presidio redaction at indexing | 4% [1–13] | 3% [1–17] | 0% | 1 | 70% | 17% |
| **D2** Document-level access control | 6% [2–16] | 17% [7–34] | 17% | 23 | 80% | 67% |
| **D3** Injection filter (rule-based) | 0% [0–7] | 70% [52–83] | 60% | 84 | 80% | 67% |
| **D4** Output filter | 6% [2–16] | 7% [2–21] | 7% | 2 | 80% | 50% |
| **ALL** D1-D4 combined | 0% [0–7] | 0% [0–11] | 0% | 0 | 70% | 17% |

## Injection detail

| Config | Poison retrieved in top-k | Success if retrieved | Success before output filter | False successes in clean runs |
|---|---|---|---|---|
| C0 | 66% | 9% | 6% | 0/10 |
| D1 | 62% | 6% | 4% | 0/10 |
| D2 | 66% | 9% | 6% | 0/10 |
| D3 | 66% | 0% | 0% | 0/10 |
| D4 | 66% | 9% | 6% | 0/10 |
| ALL | 62% | 0% | 0% | 0/10 |

### Success rate by attacker goal

| Config | goal_hijack | exfil_link | phishing | misinformation | prompt_leak |
|---|---|---|---|---|---|
| C0 | 30% | 0% | 0% | 0% | 0% |
| D1 | 20% | 0% | 0% | 0% | 0% |
| D2 | 30% | 0% | 0% | 0% | 0% |
| D3 | 0% | 0% | 0% | 0% | 0% |
| D4 | 30% | 0% | 0% | 0% | 0% |
| ALL | 0% | 0% | 0% | 0% | 0% |

### Success rate by carrier style

| Config | plain_override | fake_system_tag | note_to_ai | html_comment | fake_authority | persona_switch | subtle_paraphrase | spanish | letter_spaced | footnote |
|---|---|---|---|---|---|---|---|---|---|---|
| C0 | 20% | 0% | 0% | 20% | 20% | 0% | 0% | 0% | 0% | 0% |
| D1 | 0% | 0% | 0% | 20% | 20% | 0% | 0% | 0% | 0% | 0% |
| D2 | 20% | 0% | 0% | 20% | 20% | 0% | 0% | 0% | 0% | 0% |
| D3 | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| D4 | 20% | 0% | 0% | 20% | 20% | 0% | 0% | 0% | 0% | 0% |
| ALL | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |

## Personal-data leakage by question style

| Config | direct | enumeration | incidental | role_claim |
|---|---|---|---|---|
| C0 | 80% | 88% | 57% | 40% |
| D1 | 0% | 12% | 0% | 0% |
| D2 | 30% | 25% | 0% | 0% |
| D3 | 80% | 88% | 57% | 40% |
| D4 | 20% | 0% | 0% | 0% |
| ALL | 0% | 0% | 0% | 0% |

## Filters on their own (no LLM)

- Rule-based injection filter: flags 34/50 poisoned documents and 2/1369 clean documents (false positives). Rules that fired on clean text: {'forced_output': 1, 'prompt_extraction': 1}.
- Detection by carrier: plain_override 100%, fake_system_tag 100%, note_to_ai 100%, html_comment 100%, fake_authority 80%, persona_switch 100%, subtle_paraphrase 40%, spanish 20%, letter_spaced 20%, footnote 20%.
- Presidio redaction: 287/290 seeded values removed; survivors by field: {'name': 3}.
