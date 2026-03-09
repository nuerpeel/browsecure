from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class NetworkState(BaseModel):
    initial_url: str = Field(..., description="The URL first requested")
    final_url: str = Field(..., description="The final URL after redirects")
    redirect_chain: List[str] = Field(default_factory=list, description="Chain of URLs visited")
    requests: List[str] = Field(default_factory=list, description="All requested URLs (XHR/Fetch/WS/Resources)")

class FormState(BaseModel):
    action: Optional[str] = None
    inputs: List[str] = Field(default_factory=list)

class DOMState(BaseModel):
    snapshot_html: str = Field(..., description="The raw HTML snapshot")
    mutation_log: List[str] = Field(default_factory=list, description="Log of mutated node tags")
    iframe_tree: List[Dict[str, Any]] = Field(default_factory=list, description="Details of iframes")
    forms: List[FormState] = Field(default_factory=list)

class VisualState(BaseModel):
    screenshot_base64: Optional[str] = Field(None, description="Base64 encoded screenshot of final state")
    ocr_text: Optional[str] = Field(None, description="Extracted OCR text (simulated or real)")
    browser_geometry: Dict[str, Any] = Field(default_factory=dict, description="Viewport and overlay data")

class JSRuntimeState(BaseModel):
    dangerous_sinks_hit: List[Dict[str, str]] = Field(default_factory=list, description="Sink names and payloads")
    eval_calls: int = Field(default=0)
    canvas_fingerprinting: bool = Field(default=False)
    hidden_text_findings: List[Dict[str, str]] = Field(default_factory=list, description="Findings of prompt injections")
    bitb_overlays: List[Dict[str, Any]] = Field(default_factory=list, description="Found UI overlays mapping to BitB")
    remote_browser_canvas: bool = Field(default=False, description="True if a 100% viewport canvas is detected")

class BrowserEvidenceBundle(BaseModel):
    session_id: str
    tenant_context: str
    state_label: str = Field(default="final", description="Label for state timeline e.g. pre-click, post-click")
    network: NetworkState
    dom_state: DOMState
    visual_state: VisualState
    js_runtime: JSRuntimeState

class SessionEvidenceTimeline(BaseModel):
    session_id: str
    states: List[BrowserEvidenceBundle] = Field(default_factory=list)

class DetectionResult(BaseModel):
    detector_name: str
    severity: str = Field(..., description="Low, Medium, High, Critical")
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: List[str] = Field(default_factory=list)
    mitigation: Optional[str] = None
