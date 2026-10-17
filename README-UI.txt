IranX Panel — UI Redesign (3x-ui / Sanaei style)
================================================

What you got
------------
* main.py  — the ONLY file changed. The whole admin UI + login UI is embedded
  in it (from the "FRONTEND" section down). Nothing in the backend/API changed.
* screenshots/ — real captures of the new UI (dark / light / rail / modal / mobile).

New look
--------
* 3x-ui style shell: collapsible icon rail sidebar (66px) on desktop,
  off-canvas drawer on mobile.
* Teal-green brand accent (#008771) with three themes: dark, light, gray.
* Sticky app bar with page title + paths pill (/ws · /xh).
* Dashboard with icon stat cards, 24h traffic chart, WS/XHTTP split.
* Table-like user rows, Clean IP, proxy, live connections and events lists.
* Restyled modals, forms, switches, chips, QR / subscription dialog.
* Fully self-contained CSS (no Tailwind CDN), RTL + LTR, Vazirmatn font.
* Chart.js and qrcodejs still load from CDN (unchanged from before).

Run it
------
  pip install -r requirements.txt
  uvicorn main:app --host 0.0.0.0 --port 8899
Then open http://<your-host>:8899  (first visit asks you to set the password).

Deploy
------
Same as before: Railway / Render / any ASGI host, single main.py file.
