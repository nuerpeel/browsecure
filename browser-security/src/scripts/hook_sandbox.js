window.browserSecurityExt = {
    mutations: [],
    dangerous_sinks_hit: [],
    hidden_text_findings: [],
    bitb_overlays: []
};

// 1. Hook Mutation Observer
const observer = new MutationObserver((mutations) => {
    mutations.forEach(m => {
        if (m.target && m.target.nodeName) {
            window.browserSecurityExt.mutations.push(m.target.nodeName);
        }
    });
});
observer.observe(document, {childList: true, subtree: true});

// 2. Hook Dangerous Sinks (e.g., eval)
const originalEval = window.eval;
window.eval = function() {
    const payload = arguments[0] ? arguments[0].toString() : "";
    // Filter out our own Playwright evaluate calls
    if (!payload.includes("window.detectHiddenPromptInjections") && 
        !payload.includes("window.detectBitBOverlays") && 
        !payload.includes("window.detectRemoteBrowser") &&
        !payload.includes("window.browserSecurityExt")) {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "eval",
            payload: payload
        });
    }
    return originalEval.apply(this, arguments);
};

// Hook innerHTML via property descriptor
const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
if (originalInnerHTML && originalInnerHTML.set) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            window.browserSecurityExt.dangerous_sinks_hit.push({
                sink: "innerHTML",
                payload: value ? value.toString().substring(0, 100) : ""
            });
            return originalInnerHTML.set.call(this, value);
        },
        get: originalInnerHTML.get
    });
}

// Hook new Function
const originalFunction = window.Function;
window.Function = function(...args) {
    const payload = args[args.length - 1] ? args[args.length - 1].toString() : "";
    if (!payload.includes("window.detectHiddenPromptInjections") && 
        !payload.includes("window.detectBitBOverlays") && 
        !payload.includes("window.browserSecurityExt")) {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "new_Function",
            payload: payload.substring(0, 100)
        });
    }
    return originalFunction.apply(this, args);
};

// Hook outerHTML
const originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
if (originalOuterHTML && originalOuterHTML.set) {
    Object.defineProperty(Element.prototype, 'outerHTML', {
        set: function(value) {
            window.browserSecurityExt.dangerous_sinks_hit.push({
                sink: "outerHTML",
                payload: value ? value.toString().substring(0, 100) : ""
            });
            return originalOuterHTML.set.call(this, value);
        },
        get: originalOuterHTML.get
    });
}

// Hook insertAdjacentHTML
const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
if (originalInsertAdjacentHTML) {
    Element.prototype.insertAdjacentHTML = function(position, text) {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "insertAdjacentHTML",
            payload: text ? text.toString().substring(0, 100) : ""
        });
        return originalInsertAdjacentHTML.apply(this, arguments);
    };
}

// Hook document.write / writeln
const originalWrite = document.write;
document.write = function(str) {
    window.browserSecurityExt.dangerous_sinks_hit.push({
        sink: "document.write",
        payload: str ? str.toString().substring(0, 100) : ""
    });
    return originalWrite.apply(document, arguments);
};

const originalWriteln = document.writeln;
document.writeln = function(str) {
    window.browserSecurityExt.dangerous_sinks_hit.push({
        sink: "document.writeln",
        payload: str ? str.toString().substring(0, 100) : ""
    });
    return originalWriteln.apply(document, arguments);
};

// Hook Range.createContextualFragment
if (Range && Range.prototype && Range.prototype.createContextualFragment) {
    const originalCreateContextualFragment = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function(str) {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "Range.createContextualFragment",
            payload: str ? str.toString().substring(0, 100) : ""
        });
        return originalCreateContextualFragment.apply(this, arguments);
    };
}

// Hook iframe srcdoc assignments
const iframeSrcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
if (iframeSrcdocDesc && iframeSrcdocDesc.set) {
    Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
        set: function(value) {
            window.browserSecurityExt.dangerous_sinks_hit.push({
                sink: "iframe.srcdoc",
                payload: value ? value.toString().substring(0, 100) : ""
            });
            return iframeSrcdocDesc.set.call(this, value);
        },
        get: iframeSrcdocDesc.get
    });
}

// Hook setTimeout / setInterval when called with string
const originalSetTimeout = window.setTimeout;
window.setTimeout = function(handler, timeout) {
    if (typeof handler === 'string') {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "setTimeout(string)",
            payload: handler.toString().substring(0, 100)
        });
    }
    return originalSetTimeout.apply(this, arguments);
};

const originalSetInterval = window.setInterval;
window.setInterval = function(handler, timeout) {
    if (typeof handler === 'string') {
        window.browserSecurityExt.dangerous_sinks_hit.push({
            sink: "setInterval(string)",
            payload: handler.toString().substring(0, 100)
        });
    }
    return originalSetInterval.apply(this, arguments);
};

// Hook setAttribute for dangerous attributes and protocols
const originalSetAttribute = Element.prototype.setAttribute;
if (originalSetAttribute) {
    Element.prototype.setAttribute = function(name, value) {
        try {
            const lowerName = name ? name.toString().toLowerCase() : "";
            const valStr = value ? value.toString() : "";
            const lowerVal = valStr.toLowerCase();
            const dangerousAttr = lowerName.startsWith('on') || ["src", "href", "action", "srcdoc"].includes(lowerName);
            const dangerousProto = lowerVal.startsWith('javascript:') || lowerVal.startsWith('data:') || lowerVal.startsWith('vbscript:');
            if (dangerousAttr || dangerousProto) {
                window.browserSecurityExt.dangerous_sinks_hit.push({
                    sink: `setAttribute(${lowerName})`,
                    payload: valStr.substring(0, 100)
                });
            }
        } catch (e) {
            // swallow
        }
        return originalSetAttribute.apply(this, arguments);
    };
}

// Helper to extract remote-browser streaming characteristics (large canvas)
window.detectRemoteBrowser = function() {
    let findings = false;
    const canvases = document.querySelectorAll('canvas');
    canvases.forEach(canvas => {
        const style = window.getComputedStyle(canvas);
        const rect = canvas.getBoundingClientRect();
        // Check if canvas occupies > 80% of the viewport width/height
        if (rect.width > window.innerWidth * 0.8 && rect.height > window.innerHeight * 0.8) {
            findings = true;
        }
    });
    window.browserSecurityExt.remote_browser_canvas = findings;
    return findings;
};

// Helper to extract computed BitB overlaps since Python bs4 cannot read CSS classes easily
window.detectBitBOverlays = function() {
    let findings = [];
    const elements = document.querySelectorAll('div, iframe');
    elements.forEach(el => {
        const style = window.getComputedStyle(el);
        if (style.display !== 'none' && (style.position === 'absolute' || style.position === 'fixed')) {
            const zIndex = parseInt(style.zIndex);
            if (!isNaN(zIndex) && zIndex > 900) {
                // Highly suspicious overlay
                findings.push({
                    tag: el.tagName,
                    id: el.id,
                    className: el.className,
                    content: el.innerText ? el.innerText.substring(0, 100) : "iframe"
                });
            }
        }
    });
    window.browserSecurityExt.bitb_overlays = findings;
    return findings;
};

// 3. Prompt Injection Detector (Hidden Text)
// We will call this right before page serialization
window.detectHiddenPromptInjections = function() {
    let findings = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while (node = walker.nextNode()) {
        if (node.nodeValue && node.nodeValue.trim().length > 10) {
            const el = node.parentElement;
            if (!el) continue;
            const style = window.getComputedStyle(el);
            const text = node.nodeValue.toLowerCase();
            
            let isHidden = false;
            if (style.opacity === "0" || style.fontSize === "0px" || style.display === "none" || style.visibility === "hidden" || style.color === style.backgroundColor) {
                isHidden = true;
            }
            // Check for off-screen
            const rect = el.getBoundingClientRect();
            if (rect.left < -9000 || rect.top < -9000) {
                isHidden = true;
            }

            if (isHidden) {
                if (text.includes("ignore previous") || text.includes("system prompt") || text.includes("you are now")) {
                    findings.push({ type: "hidden_instruction", text: node.nodeValue.trim().substring(0, 200) });
                }
            }
        }
    }
    window.browserSecurityExt.hidden_text_findings = findings;
    return findings;
};
