class MockVisionService:
    def __init__(self):
        # A static map to simulate OCR finding brand impersonations based on URL or known mock states.
        # In a real environment, this would call AWS Vision, Google Cloud Vision, or GPT-4V.
        pass

    def extract_visual_metadata(self, base64_image: str, html_content: str) -> str:
        """
        Simulate OCR/Computer Vision extraction from a screenshot.
        Since we don't want to actually run Tesseract/CLIP in this test suite,
        we infer the visual context by inspecting the unrendered HTML, simulating what
        a user visually sees on screen.
        """
        metadata = []
        if "microsoft" in html_content.lower() or "office365" in html_content.lower():
            metadata.append("Visuals contain Microsoft Office 365 branding and logos.")
        
        if "acme corp" in html_content.lower():
            metadata.append("Visuals contain ACME Corp branding.")
        
        if "login" in html_content.lower() or "password" in html_content.lower() or "sso" in html_content.lower():
            metadata.append("Visuals render a credential harvesting login form.")

        if not metadata:
            return "No recognizable branding or forms detected."
            
        return " | ".join(metadata)
