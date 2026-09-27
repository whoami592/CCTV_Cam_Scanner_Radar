# CCTV Cam Scanner Radar

**Coded by Cyber Security Engineer Mr Sabaz Ali Khan**

A Python project for **authorized discovery of possible CCTV/IP-camera and NVR devices on your own private LAN**.

## Features

- Radar-style Tkinter GUI
- Private IPv4 CIDR scanning
- Hard block on public/internet IP ranges
- Maximum scan size: 1024 addresses (`/22`)
- Checks common embedded/CCTV TCP service ports
- Lightweight HTTP `HEAD /` metadata check
- Detects likely RTSP exposure on ports `554` / `8554`
- Marks devices as **possible** cameras/NVRs based on non-invasive service clues
- CSV export
- CLI mode included
- No password guessing
- No default-password testing
- No exploit attempts
- No video-stream access

## Requirements

- Python 3.9+ recommended
- Tkinter (normally included with Windows Python)
- No third-party Python packages are required

## Run GUI

```bash
python main.py
```

## Run CLI

```bash
python cli.py
```

Or specify your own **private** subnet:

```bash
python cli.py 192.168.1.0/24
```

Example:

```bash
python cli.py 10.0.0.0/24 --timeout 0.5 --workers 32
```

## What it checks

TCP connectivity only on common camera / embedded-service ports:

`80, 443, 554, 8000, 8080, 8081, 8443, 8554, 8899`

If a normal HTTP port is open, it may send a `HEAD /` request and read public response headers such as `Server` or `WWW-Authenticate`. It does **not** log in.

## Interpretation

A result marked `Possible camera/NVR` is only a heuristic. A port number by itself does not prove a device is a camera.

## Safety / Authorization

Use this tool only on networks and devices you own or have explicit permission to assess.

The code intentionally refuses public IP ranges and does not include credential attacks, exploitation, or unauthorized stream retrieval.
