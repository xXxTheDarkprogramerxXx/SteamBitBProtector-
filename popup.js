document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get(["iframeDetectionMode", "bitbDetectionMode"], settings => {
        document.getElementById('iframeDetection').checked = settings.iframeDetectionMode !== false;
        document.getElementById('bitbDetection').checked = settings.bitbDetectionMode === true;
    });

    document.getElementById('iframeDetection').addEventListener('change', e => {
        chrome.storage.local.set({ iframeDetectionMode: e.target.checked });
    });
    document.getElementById('bitbDetection').addEventListener('change', e => {
        chrome.storage.local.set({ bitbDetectionMode: e.target.checked });
    });

    document.getElementById('checkNow').addEventListener('click', () => {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            chrome.scripting.executeScript({
                target: { tabId: tabs[0].id },
                files: ['content.js']
            });
        });
    });
});
