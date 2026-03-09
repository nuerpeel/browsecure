import asyncio
import os
import uuid
import base64
from playwright.async_api import async_playwright
from src.models.evidence import (
    BrowserEvidenceBundle, SessionEvidenceTimeline, NetworkState, DOMState, 
    VisualState, JSRuntimeState, FormState
)

class BrowserOrchestrator:
    def __init__(self, headless=True):
        self.headless = headless

    async def _capture_state(self, page, session_id, url, network_requests, redirect_chain, state_label):
        # Run JS detectors
        await page.evaluate("window.detectHiddenPromptInjections()")
        await page.evaluate("window.detectBitBOverlays()")
        await page.evaluate("window.detectRemoteBrowser()")
        
        # Extract JS findings
        js_ext = await page.evaluate("window.browserSecurityExt")
        
        # DOM Extraction
        snapshot_html = await page.content()
        
        # Visual Extraction
        screenshot_bytes = await page.screenshot(full_page=True)
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

        # Assemble Bundle
        return BrowserEvidenceBundle(
            session_id=session_id,
            tenant_context="local_prototype",
            state_label=state_label,
            network=NetworkState(
                initial_url=url,
                final_url=page.url,
                redirect_chain=list(redirect_chain),
                requests=list(network_requests)
            ),
            dom_state=DOMState(
                snapshot_html=snapshot_html,
                mutation_log=js_ext.get("mutations", []),
                iframe_tree=[], # To be expanded later
                forms=[] # Extract forms via bs4 later
            ),
            visual_state=VisualState(
                screenshot_base64=screenshot_base64,
                ocr_text=None,
                browser_geometry={"viewport": "1920x1080"}
            ),
            js_runtime=JSRuntimeState(
                dangerous_sinks_hit=js_ext.get("dangerous_sinks_hit", []),
                eval_calls=len([x for x in js_ext.get("dangerous_sinks_hit", []) if x.get("sink") == "eval"]),
                canvas_fingerprinting=False,
                hidden_text_findings=js_ext.get("hidden_text_findings", []),
                bitb_overlays=js_ext.get("bitb_overlays", []),
                remote_browser_canvas=js_ext.get("remote_browser_canvas", False)
            )
        )

    async def collect_evidence(self, url: str) -> SessionEvidenceTimeline:
        session_id = str(uuid.uuid4())
        timeline = SessionEvidenceTimeline(session_id=session_id)
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=['--disable-web-security', '--disable-features=IsolateOrigins,site-per-process']
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080}
            )
            
            # Use stealth mechanisms (simplified for proto)
            await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            # Load hook script
            hook_script_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "hook_sandbox.js")
            with open(hook_script_path, "r") as f:
                hook_script = f.read()
            
            await context.add_init_script(hook_script)

            page = await context.new_page()

            # Network State tracking
            network_requests = []
            page.on("request", lambda request: network_requests.append(request.url))

            redirect_chain = []
            page.on("response", lambda response: redirect_chain.append(response.url) if response.status in [301, 302, 307, 308] else None)

            # 1. Initial Load
            print(f"[*] Navigating to {url}")
            await page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Capture Pre-Click State (State 0)
            print("[*] Extracting Pre-Interaction Evidence Bundle...")
            pre_click_state = await self._capture_state(page, session_id, url, network_requests, redirect_chain, "pre-click")
            timeline.states.append(pre_click_state)

            # 2. Candidate Discovery & Interaction (Phase 2)
            # Find actionable elements for SSO/Login
            print("[*] Searching for candidate SSO/Login elements...")
            interaction_happened = False
            try:
                # Use a broader selector for testing to handle various mock scenarios
                login_btn = None
                for text in ["SSO", "Login", "Verify", "Sign"]:
                    candidate = page.locator("button, a, input[type='submit']", has_text=text).first
                    if await candidate.count() > 0:
                        login_btn = candidate
                        break
                
                if login_btn:
                    print(f"[*] Found candidate button. Simulating click...")
                    await login_btn.click(timeout=3000)
                    interaction_happened = True
                    # Use a hard sleep to ensure DOM mutations (like setTimeouts) finish processing
                    await page.wait_for_timeout(2000)
                else:
                    print("[*] No candidate interactive button found. Waiting 1s to allow passive scripts.")
                    await page.wait_for_timeout(1000)
            except Exception as e:
                print(f"[!] Expected Error or Timeout during interaction (continuing safely): {e}")

            if interaction_happened:
                # Capture Post-Click State (State 1)
                print("[*] Extracting Post-Interaction Evidence Bundle...")
                post_click_state = await self._capture_state(page, session_id, url, network_requests, redirect_chain, "post-click")
                timeline.states.append(post_click_state)

            await browser.close()
            return timeline
