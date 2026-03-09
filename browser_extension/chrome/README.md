# PhishNet Chrome Extension (Starter)

Small starter extension that scans the current active tab URL using:
`http://localhost:8000/api/scan/scan-light`

## Load in Chrome
1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select this folder: `browser_extension/chrome`

## Use
1. Keep backend running on `localhost:8000`
2. Open any webpage
3. Click the extension icon
4. Click `Scan Current URL`

## Revert if you don't like it
1. Remove the extension from `chrome://extensions`
2. Delete this folder: `browser_extension/chrome`
3. Optionally discard git changes for this folder
