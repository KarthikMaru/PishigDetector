# PhishGuard

Simple phishing-site detection website built with plain HTML, CSS, and JavaScript.

## Features

- Browser-side URL scanning with no backend required
- Heuristic phishing detection based on hostname and URL structure
- Risk score, category, and human-readable findings
- Responsive layout for desktop and mobile

## Run locally

Open `index.html` directly in a browser, or serve the folder with a static server:

```bash
cd /Users/mkarthik/codes/phishing-detector
python3 -m http.server 8000
```

Then visit `http://localhost:8000`.

## Notes

This is a heuristic demo, not a guarantee that a site is safe or malicious. Real-world phishing detection is stronger when combined with reputation feeds, blocklists, content analysis, and server-side verification.
