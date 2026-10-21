"""Personal-data redaction with Microsoft Presidio.

Used in two places:
  * index time: every document is redacted before it is embedded, so personal
    data never enters the vector store (defence D1);
  * output time: the generated answer is redacted again (part of defence D3).

Presidio combines regex/checksum recognizers (e-mail, phone, SSN) with spaCy
NER for names and dates. We use the small spaCy model (en_core_web_sm, 12 MB)
to save disk; the large model has better name recall.
"""
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Entities we redact. ORGANIZATION/LOCATION/URL are left alone: they are noisy
# with the small spaCy model and are not personal data in this corpus.
ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "DATE_TIME", "MRN"]
SCORE_THRESHOLD = 0.35


@lru_cache(maxsize=1)
def _engines():
    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    # Medical record numbers are organisation-specific, so Presidio has no built-in
    # recognizer; a real deployment would add one for its own ID format, as here.
    analyzer.registry.add_recognizer(PatternRecognizer(
        supported_entity="MRN",
        patterns=[Pattern("mrn", r"\bMRN[-: ]?\d{6,8}\b", 0.9)],
    ))
    return analyzer, AnonymizerEngine()


def redact(text: str) -> str:
    analyzer, anonymizer = _engines()
    results = analyzer.analyze(text=text, language="en", entities=ENTITIES,
                               score_threshold=SCORE_THRESHOLD)
    operators = {e: OperatorConfig("replace", {"new_value": f"<{e}>"}) for e in ENTITIES}
    return anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text
