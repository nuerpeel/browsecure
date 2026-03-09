import os
import json
import numpy as np
from typing import Dict, Any, Tuple
from src.models.evidence import BrowserEvidenceBundle

# Quick implementation of TF-IDF / Cosine Similarity to simulate ChromaDB
from collections import Counter
import math

from src.corpus.loader import load_corpus

class NoveltyDetector:
    def __init__(self, persist_file="./data/mock_db.json"):
        self.persist_file = persist_file
        self.documents = {}
        print(f"[*] Initializing Mock VectorDB at {persist_file}")
        
        # Ensure dir exists
        os.makedirs(os.path.dirname(persist_file), exist_ok=True)
        if os.path.exists(self.persist_file):
            with open(self.persist_file, "r") as f:
                self.documents = json.load(f)
                
        # Seed DB with known corpus if empty
        if not self.documents:
            self._seed_corpus()

    def _seed_corpus(self):
        """Injects known OWASP/Promptfoo examples into the VectorDB so novel alerts can cluster around them."""
        print("[*] Seeding Mock VectorDB with security_corpus.json")
        corpus = load_corpus()
        
        for idx, entry in enumerate(corpus.get("dom_xss_sinks", [])):
            doc = f"Sinks: {entry.get('sink', '')}"
            self.documents[f"seed_sink_{idx}"] = {"text": doc.lower(), "metadata": {"type": "corpus_seed"}}
            
        for idx, pattern in enumerate(corpus.get("promptfoo_indirect_web_pwn", {}).get("example_payloads", [])):
            doc = f"Tags: {pattern}"
            self.documents[f"seed_pi_{idx}"] = {"text": doc.lower(), "metadata": {"type": "corpus_seed"}}
            
        with open(self.persist_file, "w") as f:
            json.dump(self.documents, f, indent=4)

    def _generate_document_string(self, bundle: BrowserEvidenceBundle) -> str:
        """Create a textual representation of the bundle for embedding."""
        tags = " ".join(bundle.dom_state.mutation_log)
        sinks = " ".join([s.get("sink", "") for s in bundle.js_runtime.dangerous_sinks_hit])
        doc = f"URL: {bundle.network.final_url} Tags: {tags} Sinks: {sinks}"
        return doc.lower()

    def _compute_cosine(self, text1: str, text2: str) -> float:
        """Very basic TF-IDF cosine similarity."""
        vec1 = Counter(text1.split())
        vec2 = Counter(text2.split())
        intersection = set(vec1.keys()) & set(vec2.keys())
        numerator = sum([vec1[x] * vec2[x] for x in intersection])
        
        sum1 = sum([vec1[x] ** 2 for x in list(vec1.keys())])
        sum2 = sum([vec2[x] ** 2 for x in list(vec2.keys())])
        denominator = math.sqrt(sum1) * math.sqrt(sum2)
        
        if not denominator:
            return 0.0
        else:
            return float(numerator) / denominator

    def analyze_novelty(self, bundle: BrowserEvidenceBundle) -> Tuple[str, float]:
        """
        Analyzes the bundle against historical data.
        """
        doc = self._generate_document_string(bundle)
        
        if not self.documents:
            self._store_bundle(bundle.session_id, doc, {"url": bundle.network.final_url})
            return "Genuinely Novel", 0.0

        # Find max similarity
        max_similarity = 0.0
        for sid, stored_doc in self.documents.items():
            sim = self._compute_cosine(doc, stored_doc["text"])
            if sim > max_similarity:
                max_similarity = sim

        self._store_bundle(bundle.session_id, doc, {"url": bundle.network.final_url})

        # Thresholds per Architecture Doc
        if max_similarity > 0.95:
            return "Known Family", max_similarity
        elif max_similarity > 0.85:
            return "Close Variant", max_similarity
        else:
            return "Genuinely Novel", max_similarity

    def _store_bundle(self, session_id: str, doc: str, metadata: Dict[str, Any]):
        self.documents[session_id] = {"text": doc, "metadata": metadata}
        with open(self.persist_file, "w") as f:
            json.dump(self.documents, f, indent=4)
