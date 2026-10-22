# CV entry

**RAG Copilot: Privacy & Security Testbed** · Python, MLX, LangChain, ChromaDB, Presidio, FastAPI · *in progress* · github.com/pkjx29/rag-security-testbed

- Built a local retrieval-augmented assistant over public NIST guidance (incl. SP 800-66 Rev. 2) using a 4-bit Qwen2.5-1.5B on Apple MLX. Seeded its index with synthetic patient and employee records, and wrote a 115-case benchmark covering 50 indirect prompt injections and 35 personal-data extraction attempts.
- Implemented and measured four switchable defences: Presidio redaction at indexing, document-level access control with an independent ACL check, a rule-based injection filter, and an output filter. Extraction leaks fell from 15/30 to 0/30 with all four, with NIST QA going from 9/10 to 7/10. The benchmark also documents where each defence fails: mislabelled documents, paraphrased or non-English injections, and reformatted identifiers.

<!-- Every number above comes from results/latest/report.md. Re-check after each benchmark run. -->
