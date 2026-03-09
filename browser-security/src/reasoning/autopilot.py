import json
from typing import List
from src.models.evidence import BrowserEvidenceBundle, DetectionResult
from src.retrieval.novelty import NoveltyDetector

class AutopilotEngine:
    def __init__(self):
        self.novelty_detector = NoveltyDetector()

    def generate_report(self, bundle: BrowserEvidenceBundle, det_results: List[DetectionResult], llm_result: DetectionResult) -> str:
        """Coordinates the final triage and report generation."""
        # 1. Compute Novelty
        novelty_category, similarity_score = self.novelty_detector.analyze_novelty(bundle)

        # 2. Determine Final Verdict
        all_results = det_results + ([llm_result] if llm_result else [])
        
        highest_severity = "Low"
        confidence_sum = 0
        total_findings = []
        
        severity_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        reverse_map = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        
        max_sev_val = 1
        for res in all_results:
            sev_val = severity_map.get(res.severity, 1)
            if sev_val > max_sev_val:
                max_sev_val = sev_val
            confidence_sum += res.confidence
            total_findings.extend(res.findings)
            
        highest_severity = reverse_map[max_sev_val]
        avg_confidence = (confidence_sum / len(all_results)) if all_results else 0.0
        
        verdict = "MALICIOUS" if highest_severity in ["High", "Critical"] else "BENIGN/SUSPICIOUS"

        # 3. Compile Triage Action
        if verdict == "MALICIOUS" and novelty_category == "Known Family":
            triage_action = "Auto-Blocked & Extracted IOCs"
        elif verdict == "MALICIOUS" and novelty_category == "Genuinely Novel":
            triage_action = "Promoted to Analyst Review (Novel Threat)"
        else:
            triage_action = "Logged for Monitoring"

        # 4. Generate JSON Report Structure
        report = {
            "Title": f"Browser Threat Alert: {highest_severity} Severity Event",
            "Verdict": verdict,
            "Confidence": f"{avg_confidence:.2f}",
            "Novelty": f"{novelty_category} (Similarity: {similarity_score:.2f})",
            "Triage_Action": triage_action,
            "Executive_Summary": f"A user navigated to {bundle.network.initial_url}. The system detected an overall severity of {highest_severity}.",
            "Key_Indicators": total_findings,
            "Extracted_IOCs": {
                "URLs": list(set([bundle.network.initial_url, bundle.network.final_url] + bundle.network.redirect_chain))
            },
            "Recommended_Mitigation": llm_result.mitigation if llm_result else "Review network logs."
        }
        
        return json.dumps(report, indent=4)
