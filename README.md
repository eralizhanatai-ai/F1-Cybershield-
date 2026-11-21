# F1 CyberShield

An educational telemetry security simulator created by Erali Zhanatay with AI assistance.

[Open the browser demo](https://f1-cybershield-erali-mobile.alpinechant.chatgpt.site)

## Features

- An interactive introduction to 12 car components, with an animated schematic and a transition to telemetry security.
- Telemetry for two simulated cars: speed, engine temperature and four tyre temperatures.
- Message validation and HMAC authentication with an intentionally public training key.
- Replay detection during the current application process.
- Allow, Alert and Blocked outcomes with reasons.
- A live dashboard, event details, charts and security logs.

## Run locally

Tested with Python 3.13 on Windows. The application uses the Python standard library.

```sh
python dashboard.py
```

Open http://127.0.0.1:8050 in your browser. Stop the simulation in the dashboard, then press Ctrl+C in the terminal to close the server.

`accepted_messages.json` contains accepted records from the saved session. `security_log.txt` appends Alert and Blocked events. These generated files are excluded from version control.

## Browser and mobile demo

The hosted demo begins with the interactive car anatomy introduction and then opens the live security monitor.

To preview the introduction and browser simulation from this repository, run:

```sh
python -m http.server 8000
```

Open http://127.0.0.1:8000 and select **Launch F1 CyberShield** to enter the monitor. This static preview is separate from `python dashboard.py`, which still opens the original Python-server dashboard. The browser simulation requires internet access to download Pyodide.

Use the demo link above on a phone or computer. The browser version runs the original Python modules through Pyodide/WebAssembly. Each visitor has an independent simulation; refreshing the page resets it. Export logs before closing.

`mobile.html` is a portable browser version containing the Python source and UI. It downloads Pyodide from a CDN, so internet access is required. On phones, opening local HTML depends on the file viewer and browser; the hosted link is the simplest option.

## Tests

```sh
python -m unittest -v
```

The provided suite covers the core and dashboard. The browser adaptation was also checked with the Python runtime under WebAssembly for acceptance, alerts, tampering, replay rejection and file export. Physical-phone testing remains to be completed.

## Project files

- `main.py`: validation, statuses, packet processing and logging.
- `authentication.py`: HMAC creation and verification.
- `simulator.py`: artificial telemetry generation.
- `dashboard.py` / `dashboard.html`: local server, simulation session and interface.
- `test_cybershield.py` / `test_dashboard.py`: automated tests.
- `index.html`: interactive introduction with the animated car anatomy.
- `mobile.html`: browser adaptation and a link back to the introduction.

## Scope and limitations

This is a learning and portfolio project, not a production security system or software connected to a real Formula 1 car. The shared demo key is not a production secret. Replay state does not survive restarting the application. It does not protect the whole computer or a database. Hardening and physical-device testing are future work.

## Development

I defined requirements, participated in implementation and debugging, and checked the program's behaviour. AI tools assisted with explanations, architecture, code, the interface and packaging.
