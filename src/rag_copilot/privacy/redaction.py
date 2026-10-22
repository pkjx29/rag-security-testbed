"""Personal-data detection and redaction with Microsoft Presidio.

Used in two places:
  * D1, index time: every document is redacted before it is embedded, so personal
    data never enters the protected vector store;
  * D4, output time: the generated answer is checked again.

Presidio combines regex/checksum recognizers (e-mail, phone, SSN) with spaCy NER
for names and dates. We use the small spaCy model (en_core_web_sm, 12 MB) to save
disk; the large model has better name recall. Automated detection is imperfect:
the measured miss rate is in the results.
"""
from __future__ import annotations

from collections import Counter
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ORGANIZATION/LOCATION/URL are not redacted: they are noisy with the small spaCy
# model and are not personal data in this corpus.
ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "DATE_TIME", "MRN"]
SCORE_THRESHOLD = 0.35


@lru_cache(maxsize=1)
def _engines() -> tuple[AnalyzerEngine, AnonymizerEngine]:
    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    # Medical record numbers are organisation-specific, so Presidio has no built-in
    # recognizer. This one is scoped to the "MRN-" prefix used by this hospital.
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="MRN",
        patterns=[Pattern("mrn", r"\bMRN[-: ]?\d{6,8}\b", 0.9)],
    ))
    return analyzer, AnonymizerEngine()


def detect(text: str) -> list[RecognizerResult]:
    analyzer, _ = _engines()
    return analyzer.analyze(text=text, language="en", entities=ENTITIES, score_threshold=SCORE_THRESHOLD)


def redact_with_stats(text: str) -> tuple[str, Counter]:
    """Replace each detected value with <ENTITY_TYPE>. Returns the text and counts per type."""
    _, anonymizer = _engines()
    results = detect(text)
    operators = {e: OperatorConfig("replace", {"new_value": f"<{e}>"}) for e in ENTITIES}
    redacted = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text
    return redacted, Counter(r.entity_type for r in results)


def redact(text: str) -> str:
    return redact_with_stats(text)[0]
