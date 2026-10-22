"""Logging that cannot leak personal data by accident.

Code in this project logs counts and IDs only. As a second layer, every record
passes through a filter that masks e-mail, SSN-like and phone-like strings
before it is written anywhere.
"""
import logging
import re

_PATTERNS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "<EMAIL>"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<SSN>"),
    (re.compile(r"\(?\b\d{3}\)?[ .-]?\d{3}[ .-]\d{4}\b"), "<PHONE>"),
    (re.compile(r"\bMRN[-: ]?\d{6,8}\b"), "<MRN>"),
]


def mask(text: str) -> str:
    for rx, repl in _PATTERNS:
        text = rx.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask(record.getMessage())
        record.args = None
        return True


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger


def configure(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Presidio warns once per unmapped spaCy label on every call; that is noise, not signal.
    for noisy in ("presidio-analyzer", "presidio-anonymizer", "httpx", "chromadb"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
