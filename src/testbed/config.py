"""Central configuration. Every number that affects the results lives here."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
RAW_DIR = DATA / "raw"              # downloaded NIST PDFs (not committed)
SYNTH_DIR = DATA / "synthetic"      # generated fake records (committed, deterministic)
INDEX_DIR = DATA / "index"          # ChromaDB persistent store (not committed)
CACHE_DIR = DATA / "cache"          # LLM generation cache (not committed)
RESULTS_DIR = ROOT / "results"

# Public corpus: NIST publications (US Government works, public domain).
# SHA-256 pins the exact bytes the results were produced from.
CORPUS = [
    {
        "id": "sp800-66r2",
        "title": "NIST SP 800-66r2: Implementing the HIPAA Security Rule",
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf",
        "sha256": "3910c9b29e06d978bf17258d94e851d8d3d786ceb65beb352cc93271f4d3173e",
    },
    {
        "id": "privacy-framework",
        "title": "NIST Privacy Framework v1.0",
        "url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01162020.pdf",
        "sha256": "58e1f2373e1c8a5782f7ddfce677fa9fc15e2d920ec0ab97ee754697e91bc2f0",
    },
    {
        "id": "ir8053",
        "title": "NISTIR 8053: De-Identification of Personal Information",
        "url": "https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.8053.pdf",
        "sha256": "ab7371fb6707a328ce6a75e7151b69e5c0442d3453ab4146decee328bf8b7628",
    },
    {
        "id": "ai100-2e2025",
        "title": "NIST AI 100-2e2025: Adversarial Machine Learning taxonomy",
        "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf",
        "sha256": "4811fb6ad73f9c9121843ab77e029b5adc6f2c86d33c2fc5b2099ef133847646",
    },
]

# Chunking / retrieval
CHUNK_SIZE = 900          # characters
CHUNK_OVERLAP = 150
TOP_K = 4

# Generator: small local model via Apple MLX (runs on an 8 GB M1).
MODEL_ID = "mlx-community/Qwen2.5-1.5B-Instruct-4bit"
MAX_TOKENS = 200          # greedy decoding, so outputs are deterministic and cacheable

# Synthetic data
SEED = 1337
N_PATIENT_RECORDS = 40    # access_level = restricted
N_HR_MEMOS = 10           # personal data wrongly filed as public

# Roles -> access levels they may retrieve (enforced in the vector query, not the prompt)
ROLE_ACCESS = {
    "public": ["public"],
    "clinician": ["public", "restricted"],
}

# Secret embedded in the system prompt; used to measure system-prompt leakage.
SYSTEM_CANARY = "NW-ASSIST-7731"

# Output filter: links to anything outside this list are removed.
URL_ALLOWLIST = ["nist.gov", "hhs.gov", "nvlpubs.nist.gov", "csrc.nist.gov"]
