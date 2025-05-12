(() => {
	'use strict';

// Default detectorSettings (will be overwritten by chrome.storage values if present)
const detectorSettings = { iframeDetection: true, bitbDetection: false };

// Load user detectorSettings for detection toggles from chrome.storage.local
chrome.storage.local.get(['iframeDetection', 'bitbDetection'], (res) => {
    if (res) {
        if (typeof res.iframeDetection === 'boolean') detectorSettings.iframeDetection = res.iframeDetection;
        if (typeof res.bitbDetection === 'boolean') detectorSettings.bitbDetection = res.bitbDetection;
    }
    initializeDetection();
});

// Listen for runtime changes in detectorSettings (in case user toggles via popup while page is open)
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
        if (changes.iframeDetection) detectorSettings.iframeDetection = changes.iframeDetection.newValue;
        if (changes.bitbDetection) detectorSettings.bitbDetection = changes.bitbDetection.newValue;
    }
});

function detectSimulatedBrowserWindows() {
    const potentialWindows = document.querySelectorAll('div, section, article');
    potentialWindows.forEach(elem => {
        const style = window.getComputedStyle(elem);
        if ((style.position === 'fixed' || style.position === 'absolute') &&
            parseInt(style.zIndex) > 1000 &&
            elem.innerText.includes('Sign in to Steam')) {
            triggerPhishingWarning('bitb', 'Simulated browser window detected.');
        }
    });
}


function checkSteamApiScams() {
    try {
        const host = window.location.hostname.toLowerCase();
        const query = window.location.search;
        if (host.includes("steam") && !['steamcommunity.com', 'steampowered.com', 'steamusercontent.com', 'steamgames.com', 'steam.com'].some(dom => host.endsWith(dom))) {
            triggerPhishingWarning('Steam Scam Domain', `Suspicious Steam-like domain detected: ${host}`);
        }
        const keyMatch = query.match(/[?&](?:apikey|api[_-]?key|key)=([^&]+)/i);
        if (keyMatch && keyMatch[1].length > 20) {
            triggerPhishingWarning('Steam API Key Leak', 'Possible Steam API key found in URL. Scam attempt detected!');
        }
        const bodyText = document.body ? document.body.innerText : '';
        if (/Steam\s*API\s*Key/i.test(bodyText)) {
            triggerPhishingWarning('Steam API Key Scam', 'Page is trying to request your Steam API Key. Scam attempt detected!');
        }
        document.querySelectorAll('input, textarea').forEach(inp => {
            const placeholder = inp.placeholder || '';
            const nameAttr = inp.name || '';
            if (/api[\s_-]?key/i.test(placeholder) || /api[\s_-]?key/i.test(nameAttr)) {
                triggerPhishingWarning('Steam API Key Scam', 'Input field requesting Steam API Key detected. Scam attempt detected!');
            }
        });
    } catch(e) { console.error('Steam API scam check failed:', e); }
}
function detectNextGenBitB() {
    try {
        const onSteamDomain = /(^|\.)steamcommunity\.com$/.test(location.hostname) ||
                              /(^|\.)steampowered\.com$/.test(location.hostname);
        if (onSteamDomain) return false; // do not trigger on real Steam

        let suspicious = false;

        // 1️⃣ Detect full-screen scam iframe (common on tapszone & clones)
        document.querySelectorAll('iframe').forEach(iframe => {
            const src = iframe.src || '';
            if (src.includes('jahreedition.com') || src.includes('steam')) {
                if (!onSteamDomain) suspicious = true;
            }
        });

        // 2️⃣ Detect fake draggable modal + high z-index fixed windows
        document.querySelectorAll('div, section, article').forEach(el => {
            const style = window.getComputedStyle(el);
            const zIndex = parseInt(style.zIndex) || 0;
            if ((style.position === 'fixed' || style.position === 'absolute') &&
                zIndex > 100000 &&
                el.offsetWidth > 300 && el.offsetHeight > 200) {
                // Very likely a fake modal window
                suspicious = true;
            }
        });

        // 3️⃣ Detect fake URL bar using contenteditable divs with steamcommunity.com text
        document.querySelectorAll('div[contenteditable="true"]').forEach(el => {
            const text = (el.innerText || "").toLowerCase();
            if (text.includes("steamcommunity.com")) {
                suspicious = true;
            }
        });

        // 4️⃣ Detect known scam class: modal-window-content-fix_border (used by tapszone)
        if (document.querySelector('.modal-window-content-fix_border')) {
            suspicious = true;
        }

        // 5️⃣ Detect if pushState was called to inject steamcommunity.com URL
        if (location.href.includes('steamcommunity.com') && !onSteamDomain) {
            suspicious = true;
        }

        return suspicious;
    } catch (e) {
        console.error("detectNextGenBitB() failed:", e);
        return false;
    }
}


/** Initializes scanning and observers based on current detectorSettings. */
function initializeDetection() {
    if (detectorSettings.iframeDetection) {
        scanAllIframes();
    }
    if (detectorSettings.bitbDetection) {
        scanForBitBOverlays();
		detectSimulatedBrowserWindows();
    }
	if (detectNextGenBitB()) {
		triggerPhishingWarning('nextgen-bitb', 'Next-Gen Steam Browser-in-the-Browser phishing attack detected!');
	}

	  // ✅ ADD THIS LINE:
    checkSteamApiScams();
	
    // Set up a MutationObserver to catch added/modified iframes or overlay elements
    const observer = new MutationObserver(mutations => {
        for (const mutation of mutations) {
            if (mutation.type === 'childList') {
                for (const node of mutation.addedNodes) {
                    if (!(node instanceof Element)) continue;
                    // If a new iframe is added, check it
                    if (detectorSettings.iframeDetection && node.tagName === 'IFRAME') {
                        checkIframe(node);
                    }
                    // If any new element is added, it might be a part of a fake overlay
                    if (detectorSettings.bitbDetection) {
                        checkBitBElement(node);
                    }
                }
            } else if (mutation.type === 'attributes') {
                const target = mutation.target;
                if (!(target instanceof Element)) continue;
                // If an existing iframe's attributes changed (src or style), re-check it
                if (detectorSettings.iframeDetection && target.tagName === 'IFRAME' &&
                    (mutation.attributeName === 'src' || mutation.attributeName === 'style' || mutation.attributeName === 'class')) {
                    checkIframe(target);
                }
                // If any element's class/style changed (could be an overlay appearing), re-check if relevant
                if (detectorSettings.bitbDetection && (mutation.attributeName === 'style' || mutation.attributeName === 'class')) {
                    checkBitBElement(target);
                }
            }
        }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
}

/** Scans all iframes on the page for phishing characteristics. */
function scanAllIframes() {
    const iframes = document.getElementsByTagName('iframe');
    for (const iframe of iframes) {
        checkIframe(iframe);
    }
}

/** Scans the DOM for potential BITB overlay elements (large fixed/absolute containers with suspicious content). */
function scanForBitBOverlays() {
    // Check common container elements that could serve as fake browser windows
    const candidates = document.querySelectorAll('div, section, form, main, article');
    for (const elem of candidates) {
        checkBitBElement(elem);
    }
}

/** Checks a single iframe element for cross-domain full-screen phishing behavior. */
function checkIframe(iframe) {
    try {
        if (!(iframe instanceof HTMLIFrameElement)) return;
        const srcAttr = iframe.getAttribute('src');
        if (!srcAttr || srcAttr.trim() === '' || srcAttr.startsWith('about:') || srcAttr.startsWith('javascript:')) {
            // Empty or safe src (about:blank, etc) – nothing to check yet
            return;
        }
        // Determine the iframe's source hostname
        let iframeHost = '';
        try {
            const url = new URL(srcAttr, document.baseURI);  // resolves relative URLs
            iframeHost = url.hostname;
        } catch (e) {
            // If srcAttr is not a valid URL, skip
            return;
        }
        const pageHost = window.location.hostname;
        if (!iframeHost || !pageHost) return;
        // If the iframe is from a different domain than the page
        if (iframeHost !== pageHost) {
            const rect = iframe.getBoundingClientRect();
            const viewportWidth  = window.innerWidth || document.documentElement.clientWidth;
            const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
            // Check if iframe covers a significant portion of the viewport (heuristic for fullscreen/modal)
            const coversWidth  = rect.width  >= viewportWidth * 0.8;
            const coversHeight = rect.height >= viewportHeight * 0.8;
            if (coversWidth && coversHeight) {
                // Cross-domain large iframe detected – trigger warning
                triggerPhishingWarning('iframe', iframeHost);
            }
        }
    } catch (err) {
        console.error('Error during iframe check:', err);
    }
}

/** Checks an element for characteristics of a fake browser window (BITB overlay). */
function checkBitBElement(elem) {
    try {
        if (!(elem instanceof HTMLElement)) return;
        const style = window.getComputedStyle(elem);
        // Only consider elements that are fixed or absolute positioning (likely overlays)
        if (style.position !== 'fixed' && style.position !== 'absolute') return;
        // Skip if not visible or too small
        if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) return;
        const rect = elem.getBoundingClientRect();
        if (rect.width < 100 || rect.height < 100) return;  // not large enough to resemble a window
        // Gather text content for analysis
        const textContent = elem.innerText || '';
        // Check for presence of known trusted domain names in the text (fake address bars or prompts)
        const suspiciousDomains = ['accounts.google.com', 'steamcommunity.com', 'facebook.com', 'paypal.com', 'microsoftonline.com', 'apple.com', 'icloud.com'];
        for (const domain of suspiciousDomains) {
            if (textContent.includes(domain)) {
                // Found a suspicious domain string in a large overlay element – trigger warning
                triggerPhishingWarning('bitb', domain);
                break;
            }
        }
    } catch (err) {
        console.error('Error during BITB element check:', err);
    }
}

// Flag to ensure we only display one overlay per page (to avoid spamming multiple warnings)
let warningDisplayed = false;

/**
 * Triggers the security warning overlay and logging when a phishing attempt is detected.
 * @param {'iframe'|'bitb'} type - The type of detection triggered (iframe or bitb).
 * @param {string} info - Details about the detected threat (e.g. iframe hostname or spoofed domain).
 */
function triggerPhishingWarning(type, info) {
    // Log to console
    console.warn(`Phishing attempt detected (type: ${type}, domain: ${info})`);
    // Log to persistent storage (append to an array of attempts)
    try {
        chrome.storage.local.get({ phishingAttempts: [] }, (res) => {
            const attempts = res.phishingAttempts;
            attempts.push({
                type: type,
                info: info,
                page: window.location.href,
                time: new Date().toISOString()
            });
            chrome.storage.local.set({ phishingAttempts: attempts });
        });
    } catch (e) {
        console.error('Could not log phishing attempt to storage:', e);
    }
    // If an overlay is already shown, do not show another
    if (warningDisplayed) return;
    warningDisplayed = true;

    // Create a full-screen overlay div
    const overlay = document.createElement('div');
    overlay.id = 'phishing-warning-overlay';
    Object.assign(overlay.style, {
        position: 'fixed',
        top: '0', left: '0', width: '100%', height: '100%',
        backgroundColor: 'rgba(0, 0, 0, 0.85)',
        color: '#FFFFFF',
        zIndex: '2147483647',  // ensure it's on top of any existing content
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        padding: '20px'
    });
    // Warning title
    const title = document.createElement('h1');
    title.textContent = '⚠️ Security Warning!';
    title.style.marginBottom = '0.5em';
    // Main message
    const message = document.createElement('p');
    message.textContent = 'A suspicious login window was detected on this page.';
    message.style.fontSize = '1.2em';
    message.style.maxWidth = '600px';
    // Detail about the threat
    const detail = document.createElement('p');
    detail.style.fontSize = '1.1em';
    detail.style.marginTop = '1em';
    if (type === 'iframe') {
        detail.textContent = `Untrusted content from "${info}" is being displayed as a login prompt.`;
    } else {  // 'bitb'
        detail.textContent = `This page is attempting to impersonate "${info}" in a fake browser window.`;
    }
    // Advice instruction
    const instruction = document.createElement('p');
    instruction.textContent = 'For your safety, do NOT enter any credentials. You should close this page immediately.';
    instruction.style.marginTop = '1.5em';
    instruction.style.maxWidth = '600px';
    instruction.style.fontStyle = 'italic';
    // Dismiss button (allows user to close the warning overlay)
    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = 'Dismiss Warning';
    dismissBtn.style.marginTop = '2em';
    dismissBtn.style.padding = '0.6em 1.2em';
    dismissBtn.style.fontSize = '1em';
    dismissBtn.style.cursor = 'pointer';
    // Clicking the button will remove the overlay (user can then interact with the page again, if they choose to ignore the risk)
    dismissBtn.onclick = () => overlay.remove();

    // Assemble the overlay content
    overlay.appendChild(title);
    overlay.appendChild(message);
    overlay.appendChild(detail);
    overlay.appendChild(instruction);
    overlay.appendChild(dismissBtn);
    document.body.appendChild(overlay);

    // Optional: Audio alert (short beep)
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
            const audioCtx = new AudioCtx();
            const oscillator = audioCtx.createOscillator();
            oscillator.type = 'sine';
            oscillator.frequency.value = 440;  // tone at 440 Hz
            oscillator.connect(audioCtx.destination);
            oscillator.start();
            oscillator.stop(audioCtx.currentTime + 0.2);  // play for 0.2s
        }
    } catch (e) {
        // Audio might be blocked by browser autoplay policy or not supported
        console.error('Audio alert failed:', e);
    }
    // Optional: Vibration feedback (if supported, typically on mobile)
    if (navigator.vibrate) {
        navigator.vibrate(200);  // vibrate for 200ms
    }
}
})();