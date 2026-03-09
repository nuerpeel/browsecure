import asyncio
import argparse
import os, json
from src.orchestrator.sandbox import BrowserOrchestrator
from src.detectors.pipeline import DeterministicPipeline
from src.reasoning.analyzer import LLMAnalyzer
from src.reasoning.autopilot import AutopilotEngine

async def run_pipeline(url: str, headless: bool):
    print(f"========== BROWSER SECURITY PIPELINE ==========")
    print(f"Target URL: {url}")
    
    # 1. Orchestration & Collection
    orchestrator = BrowserOrchestrator(headless=headless)
    print("\n[1] Starting Interaction-Aware Collection...")
    bundle = await orchestrator.collect_evidence(url)
    print(f"[*] Bundle Extracted (Session ID: {bundle.session_id})")

    # Save raw evidence bundle to disk
    os.makedirs("reports", exist_ok=True)
    evidence_path = os.path.join("reports", f"evidence_{bundle.session_id}.json")
    with open(evidence_path, "w") as f:
        json.dump(bundle.dict(), f, indent=4)
    print(f"[*] Evidence bundle saved to: {evidence_path}")

    # 2. Deterministic Pipeline
    print("\n[2] Running Deterministic Detectors...")
    detector = DeterministicPipeline()
    det_results = detector.run_all(bundle)
    for res in det_results:
        print(f"  -> {res.detector_name} [{res.severity}]: {len(res.findings)} finding(s)")

    # 3. LLM Reasoning Layer
    print("\n[3] Engaging Multimodal LLM Reasoning Layer...")
    # analyzer = LLMAnalyzer(use_mock=True) # Will automatically check for OPENAI_API_KEY inside
    analyzer = LLMAnalyzer()  # Auto-detects: uses real OpenAI if key found in env or .vscode/launch.json, otherwise mocks
    llm_result = analyzer.analyze_evidence(bundle)
    print(f"  -> LLM Verdict [{llm_result.severity}]: {llm_result.mitigation}")

    # 4. Autopilot Novelty & Triage
    print("\n[4] Generating Autopilot Triage Report & Novelty Detection...")
    autopilot = AutopilotEngine()
    
    # Grab final state to pass to autopilot
    final_state = bundle.states[-1] if hasattr(bundle, 'states') else bundle
    final_report = autopilot.generate_report(final_state, det_results, llm_result)
    
    print("\n========== FINAL TRIAGE REPORT ==========")
    print(final_report)
    print("=========================================")
    
    # Save report to disk
    os.makedirs("reports", exist_ok=True)
    report_path = os.path.join("reports", f"report_{final_state.session_id}.json")
    with open(report_path, "w") as f:
        f.write(final_report)
    print(f"[*] Report saved successfully to: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="End-to-End Browser Security Detector Prototype")
    parser.add_argument("url", type=str, help="The target URL to analyze")
    parser.add_argument("--headed", action="store_true", help="Run Chromium in headed mode for visual debugging")
    
    args = parser.parse_args()
    
    asyncio.run(run_pipeline(args.url, headless=not args.headed))
