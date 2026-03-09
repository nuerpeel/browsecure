import pytest
import asyncio
import os
import json
from src.orchestrator.sandbox import BrowserOrchestrator
from src.detectors.pipeline import DeterministicPipeline
from src.reasoning.analyzer import LLMAnalyzer
from src.reasoning.autopilot import AutopilotEngine

# Setup paths to mock files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK_ATTACK_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_attack_page.html')}"
MOCK_BENIGN_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_benign.html')}"
MOCK_DELAYED_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_delayed_dom_xss.html')}"
MOCK_OWASP_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_owasp_sinks.html')}"
MOCK_PROMPTFOO_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_promptfoo_hidden.html')}"
MOCK_REMOTE_BROWSER_URL = f"file://{os.path.join(BASE_DIR, 'tests', 'mock_remote_browser.html')}"


@pytest.fixture
def orchestrator():
    return BrowserOrchestrator(headless=True)

@pytest.fixture
def deterministic_pipeline():
    return DeterministicPipeline()

@pytest.fixture
def autopilot():
    # Setup test-specific mock db
    import src.retrieval.novelty as novelty
    novelty.NoveltyDetector.__init__.__defaults__ = ("./data/test_mock_db.json",)
    return AutopilotEngine()

@pytest.mark.asyncio
async def test_benign_page(orchestrator, deterministic_pipeline, autopilot):
    """Test that a normal enterprise login page does not trigger alerts."""
    timeline = await orchestrator.collect_evidence(MOCK_BENIGN_URL)
    final_state = timeline.states[-1]
    
    # 1. Check Bundle Schema
    assert final_state.session_id is not None
    assert final_state.network.initial_url == MOCK_BENIGN_URL
    assert final_state.js_runtime.eval_calls == 0
    
    # 2. Check Deterministic Pipeline
    det_results = deterministic_pipeline.run_all(timeline)
    assert len(det_results) == 0, f"Expected 0 findings on benign page, got {det_results}"
    
    # 3. Check LLM Analyzer Mock (incorporates Multimodal logic)
    analyzer = LLMAnalyzer(use_mock=True)
    llm_result = analyzer.analyze_evidence(timeline)
    assert llm_result.severity in ["Low", "Medium"]  # Mock might say Medium if it sees a redirect or similar, but typically Low for purely benign.
    
    # 4. Check Final Report
    report_json = autopilot.generate_report(final_state, det_results, llm_result)
    report = json.loads(report_json)
    
    assert report["Verdict"] == "BENIGN/SUSPICIOUS"

@pytest.mark.asyncio
async def test_complex_attack_page(orchestrator, deterministic_pipeline, autopilot):
    """Test the full comprehensive attack payload (BitB, PI, Evals)."""
    timeline = await orchestrator.collect_evidence(MOCK_ATTACK_URL)
    final_state = timeline.states[-1]
    
    # 1. Check Bundle Schema
    assert final_state.js_runtime.eval_calls > 0
    assert len(final_state.js_runtime.hidden_text_findings) > 0
    assert len(final_state.js_runtime.bitb_overlays) > 0
    
    # 2. Check Deterministic Pipeline
    det_results = deterministic_pipeline.run_all(timeline)
    assert len(det_results) == 3, "Expected Sinks, Prompt Injection, and BitB detectors to fire."
    
    severities = [res.severity for res in det_results]
    assert "Critical" in severities
    assert "High" in severities

    # 3. Check Final Report
    analyzer = LLMAnalyzer(use_mock=True)
    llm_result = analyzer.analyze_evidence(timeline)
    report_json = autopilot.generate_report(final_state, det_results, llm_result)
    report = json.loads(report_json)
    
    assert report["Verdict"] == "MALICIOUS"
    assert "Critical" in report["Title"]

@pytest.mark.asyncio
async def test_delayed_dom_xss_page(orchestrator, deterministic_pipeline):
    """Test that clicking a button triggering delayed setTimeout mutations is caught in post-click timeline."""
    timeline = await orchestrator.collect_evidence(MOCK_DELAYED_URL)
    
    # Assert timeline captured both pre-click and post-click states
    assert len(timeline.states) >= 2
    post_click_state = timeline.states[-1]
    
    # Ensure innerHTML injection was caught
    sinks = [s.get("sink") for s in post_click_state.js_runtime.dangerous_sinks_hit]
    assert "innerHTML" in sinks
    
    # Ensure PI via ARIA class was caught
    pi_findings = [t.get("text") for t in post_click_state.js_runtime.hidden_text_findings]
    assert any("Ignore all safety protocols" in str(text) for text in pi_findings)
    
    det_results = deterministic_pipeline.run_all(timeline)
    assert len(det_results) == 2, "Expected Sinks and Prompt Injection to fire."

@pytest.mark.asyncio
async def test_owasp_sinks(orchestrator, deterministic_pipeline):
    """Test that the updated JS hooks catch new Function, document.write, and setAttribute."""
    timeline = await orchestrator.collect_evidence(MOCK_OWASP_URL)
    final_state = timeline.states[-1]
    
    sinks = [s.get("sink") for s in final_state.js_runtime.dangerous_sinks_hit]
    assert "document.write" in sinks, "Failed to hook document.write"
    assert "new_Function" in sinks, "Failed to hook new Function"
    assert "setAttribute(href)" in sinks or "setAttribute_href" in sinks, "Failed to catch setAttribute(href, javascript:...)"
    assert "setAttribute(onmouseover)" in sinks or "setAttribute_onmouseover" in sinks, "Failed to catch setAttribute(onmouseover, ...)"
    assert "iframe.srcdoc" in sinks or "iframe_srcdoc" in sinks, "Failed to catch iframe.srcdoc"
    
    det_results = deterministic_pipeline.run_all(timeline)
    assert len(det_results) >= 1
    assert "Dangerous Sinks Detector" in [r.detector_name for r in det_results]

@pytest.mark.asyncio
async def test_promptfoo_hidden_injection(orchestrator, deterministic_pipeline):
    """Test that promptfoo HTML comment and extreme alt-text techniques trigger corpus rules."""
    timeline = await orchestrator.collect_evidence(MOCK_PROMPTFOO_URL)
    
    det_results = deterministic_pipeline.run_all(timeline)
    
    # The corpus-backed pipeline should catch this via text extraction scanning
    pi_hits = [r for r in det_results if "Prompt Injection" in r.detector_name]
    assert len(pi_hits) > 0, "Failed to detect Promptfoo corpus PI vectors in HTML."

@pytest.mark.asyncio
async def test_remote_browser_canvas(orchestrator, deterministic_pipeline):
    """Test that a full-viewport canvas with minimal DOM (noVNC/Kasm-like) is flagged."""
    timeline = await orchestrator.collect_evidence(MOCK_REMOTE_BROWSER_URL)
    final_state = timeline.states[-1]
    
    # The JS hook should detect the large canvas
    assert final_state.js_runtime.remote_browser_canvas is True, "Failed to detect large canvas element"
    
    det_results = deterministic_pipeline.run_all(timeline)
    remote_hits = [r for r in det_results if "Remote Browser" in r.detector_name]
    assert len(remote_hits) > 0, "Failed to detect remote browser streaming via canvas."
    assert remote_hits[0].severity == "High"

@pytest.mark.asyncio
async def test_aitm_redirect_chain(deterministic_pipeline):
    """Test that a multi-hop redirect chain is flagged as AiTM without needing a real HTTP server.
    We construct a synthetic BrowserEvidenceBundle with a redirect chain directly."""
    from src.models.evidence import (
        BrowserEvidenceBundle, SessionEvidenceTimeline, NetworkState, DOMState,
        VisualState, JSRuntimeState
    )
    
    synthetic_bundle = BrowserEvidenceBundle(
        session_id="test-aitm-redirect",
        tenant_context="test",
        state_label="final",
        network=NetworkState(
            initial_url="http://bit.ly/sus_link",
            final_url="https://login-ms-secure.net/auth",
            redirect_chain=[
                "http://bit.ly/sus_link",
                "https://evil-proxy.com/redirect",
                "https://login-ms-secure.net/auth"
            ],
            requests=[]
        ),
        dom_state=DOMState(snapshot_html="<html><body>Sign in</body></html>", mutation_log=[]),
        visual_state=VisualState(),
        js_runtime=JSRuntimeState()
    )
    
    timeline = SessionEvidenceTimeline(session_id="test-aitm-redirect", states=[synthetic_bundle])
    
    det_results = deterministic_pipeline.run_all(timeline)
    aitm_hits = [r for r in det_results if "AiTM" in r.detector_name or "Redirect" in r.detector_name]
    assert len(aitm_hits) > 0, "Failed to detect AiTM redirect chain."
    assert aitm_hits[0].severity == "Medium"
    assert "3 hops" in aitm_hits[0].findings[0]

@pytest.mark.asyncio
async def test_report_saved_to_disk(orchestrator, deterministic_pipeline, autopilot):
    """Test that the autopilot report is correctly saved to the reports/ directory."""
    timeline = await orchestrator.collect_evidence(MOCK_ATTACK_URL)
    final_state = timeline.states[-1]
    
    det_results = deterministic_pipeline.run_all(timeline)
    analyzer = LLMAnalyzer(use_mock=True)
    llm_result = analyzer.analyze_evidence(timeline)
    report_json = autopilot.generate_report(final_state, det_results, llm_result)
    
    # Save the report
    os.makedirs("reports", exist_ok=True)
    report_path = os.path.join("reports", f"report_{final_state.session_id}.json")
    with open(report_path, "w") as f:
        f.write(report_json)
    
    assert os.path.exists(report_path), "Report file was not saved to disk."
    
    with open(report_path, "r") as f:
        saved = json.load(f)
    assert saved["Verdict"] == "MALICIOUS"
    
    # Cleanup
    # os.remove(report_path)
