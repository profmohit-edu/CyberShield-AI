# CyberShield AI — Ideathon Proposal

A final-submission, exactly four-page A4 proposal for **CyberShield AI: Explainable AI Copilot for Smart Contract Security**, submitted to INNOSTORM 2026 by Mohit Tiwari.

## Deliverables

- `index.html` — editable proposal structure and all product UI mockups
- `styles.css` — print and screen styling with local Poppins/Inter fonts
- `proposal.pdf` — print-ready A4 PDF (exactly four pages)
- `assets/logo.svg` — editable vector brand mark
- `assets/architecture.svg` — editable reference architecture
- `assets/workflow.svg` — editable five-stage workflow
- `assets/icons/icons.svg` — reusable SVG icon sprite
- `assets/images/dashboard.png` — high-resolution prototype preview
- `assets/fonts/` — locally packaged Poppins and Inter font files

## Preview

Open `index.html` in a modern Chromium-based browser. The on-screen canvas shows four separate A4 artboards.

## Export the PDF

From this directory, run:

```bash
google-chrome-stable --headless --no-sandbox \
  --disable-gpu --print-to-pdf=proposal.pdf \
  --print-to-pdf-no-header file://$PWD/index.html
```

In a browser print dialog, use:

- Paper: A4
- Margins: None
- Scale: 100%
- Background graphics: On
- Headers and footers: Off

## Edit the proposal

Brand colors are CSS variables at the top of `styles.css`. Text and interface content live in clearly labeled page sections inside `index.html`. All diagrams and icons are SVG and can be edited in Figma, Illustrator, Inkscape, or any text editor.

## Design system

- Primary: `#0B5FFF`
- Secondary: `#00C2FF`
- Accent: `#7C3AED`
- Headings: Poppins
- Body: Inter
- Page size: 210 × 297 mm
