from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from src.models.evidence import BrowserEvidenceBundle, DetectionResult
from src.corpus.loader import load_corpus

class DeterministicPipeline:
    def __init__(self, corpus: Optional[Dict[str, Any]] = None):
        # Load the curated corpus once (can be overridden for tests)
        self.corpus: Dict[str, Any] = corpus or load_corpus()
        self.prompt_patterns = self._build_prompt_patterns()
        self.promptfoo_payloads = self._build_promptfoo_payloads()
        self.dom_sinks = self._build_dom_sinks()

    def run_all(self, timeline) -> List[DetectionResult]:
        states = timeline.states if hasattr(timeline, 'states') else [timeline]
        
        results: List[DetectionResult] = []
        
        all_sinks = []
        all_pi_findings = []
        all_bitb = []

        for state in states:
            all_sinks.extend(state.js_runtime.dangerous_sinks_hit)
            pi_results = self._detect_prompt_injection(state)
            all_pi_findings.extend(pi_results)
            all_bitb.extend(state.js_runtime.bitb_overlays)

        # Deduplicate generic dictionary lists securely by stringifying or tuple conversion
        all_sinks = [dict(t) for t in {tuple(d.items()) for d in all_sinks}]
        all_bitb = [dict(t) for t in {tuple(d.items()) for d in all_bitb}]
        all_pi_findings = list(set(all_pi_findings))

        # 1) JS Runtime + corpus-backed dangerous sinks
        sink_hits_from_corpus = self._detect_dom_sinks(all_sinks)
        if all_sinks or sink_hits_from_corpus:
            example_sinks = [s.get("sink") for s in all_sinks[:3]] if all_sinks else []
            corpus_sinks = [h.get("sink") for h in sink_hits_from_corpus]
            findings = []
            if all_sinks:
                findings.append(
                    f"Found {len(all_sinks)} execution(s) of dangerous sinks. Examples: {example_sinks}"
                )
            if corpus_sinks:
                findings.append(f"Corpus-matched sinks observed: {list(set(corpus_sinks))}")
            results.append(
                DetectionResult(
                    detector_name="Dangerous Sinks Detector",
                    severity="High",
                    confidence=0.8,
                    findings=findings,
                )
            )

        # 2) Hidden text + corpus-backed prompt injection markers
        if all_pi_findings:
            results.append(
                DetectionResult(
                    detector_name="Prompt Injection Detector",
                    severity="Critical",
                    confidence=0.9,
                    findings=all_pi_findings,
                )
            )

        # 3) BitB / Layout Heuristics via DOM Analysis
        if all_bitb:
            results.append(DetectionResult(
                detector_name="Browser-in-the-Browser (BitB) Layout Detector",
                severity="High",
                confidence=0.85,
                findings=[f"Found high z-index absolute overlays indicating possible fake window: {[o.get('id') or o.get('className') for o in all_bitb]}"]
            ))

        # 4) Remote Browser / Canvas Streaming Detection
        any_remote_canvas = any(s.js_runtime.remote_browser_canvas for s in states)
        if any_remote_canvas:
            results.append(DetectionResult(
                detector_name="Remote Browser Streaming Detector",
                severity="High",
                confidence=0.80,
                findings=["Large canvas element (>80% viewport) detected with minimal DOM nodes. Possible noVNC/Kasm remote browser stream."]
            ))

        # 5) Suspicious Redirect Chain / AiTM Detection
        for state in states:
            chain = state.network.redirect_chain
            if len(chain) >= 2:
                results.append(DetectionResult(
                    detector_name="AiTM / Redirect Chain Detector",
                    severity="Medium",
                    confidence=0.70,
                    findings=[f"Suspicious redirect chain with {len(chain)} hops detected: {chain[:5]}"]
                ))
                break  # Only report once

        return results

    # --- corpus-backed helpers ---

    def _build_prompt_patterns(self) -> List[str]:
        patterns: List[str] = []
        for entry in self.corpus.get("prompt_injection_patterns", []):
            patterns.extend(entry.get("examples", []) or [])
            patterns.extend(entry.get("signals", []) or [])
        return [p.lower() for p in patterns if p]

    def _build_promptfoo_payloads(self) -> List[str]:
        section = self.corpus.get("promptfoo_indirect_web_pwn", {}) or {}
        payloads = section.get("example_payloads", []) or []
        carriers = section.get("embedding_techniques", []) or []
        return [p.lower() for p in payloads + carriers if p]

    def _build_dom_sinks(self) -> List[str]:
        sinks: List[str] = []
        for entry in self.corpus.get("dom_xss_sinks", []) or []:
            sink = entry.get("sink")
            if sink:
                sinks.append(sink.lower())
        return sinks

    def _detect_dom_sinks(self, js_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for ev in js_events or []:
            sink_name = (ev.get("sink") or ev.get("event") or "").lower()
            for sink in self.dom_sinks:
                if sink and sink in sink_name:
                    hits.append({"category": "dom_xss_sink", "sink": sink, "detail": ev})
        return hits

    def _detect_prompt_injection(self, bundle: BrowserEvidenceBundle) -> List[str]:
        findings: List[str] = []

        # Hidden text findings from runtime hooks
        for t in bundle.js_runtime.hidden_text_findings:
            text = t.get("text")
            if text:
                findings.append(f"Hidden prompt injection instructions found: {text}")

        # Scan DOM snapshot for corpus patterns
        dom_html = bundle.dom_state.snapshot_html or ""
        dom_text = self._extract_text(dom_html)
        corpus_cues = self.prompt_patterns + self.promptfoo_payloads
        lowered = dom_text.lower()
        matched = {p for p in corpus_cues if p and p in lowered}
        if matched:
            findings.append(f"Corpus prompt-injection cues present: {sorted(matched)}")

        return findings

    def _extract_text(self, html: str) -> str:
        if not html:
            return ""
        from bs4 import Comment
        soup = BeautifulSoup(html, "html.parser")
        text_parts = [soup.get_text(" ", strip=True)]
        
        # Also extract hidden HTML comments (crucial for Promptfoo tests)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for c in comments:
            text_parts.append(str(c))
            
        # Also extract alt attributes (crucial for Promptfoo image hiding)
        for img in soup.find_all("img"):
            if img.get("alt"):
                text_parts.append(img.get("alt"))
                
        return " ".join(text_parts)
