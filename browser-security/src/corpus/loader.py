from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

# Default path resolves to repo_root/data/corpus/security_corpus.json
DEFAULT_CORPUS_PATH = Path(__file__).resolve().parents[2] / "data" / "corpus" / "security_corpus.json"


@lru_cache(maxsize=1)
def load_corpus(path: Optional[str] = None) -> Dict[str, Any]:
    corpus_path = Path(path) if path else DEFAULT_CORPUS_PATH
    if not corpus_path.exists():
        raise FileNotFoundError(f"Corpus file not found at {corpus_path}")
    with corpus_path.open("r", encoding="utf-8") as f:
        return json.load(f)
