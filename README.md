# MemScanKit

MemScanKit is a small, traditional Windows memory scanner written in C++ using Win32, DirectX 11, and Dear ImGui. It demonstrates low‑level process inspection fundamentals: process/module discovery, value scanning, narrowing, and basic level‑1 pointer resolution, all rendered through a lightweight overlay.

## Features

* External process attachment by executable name
* Module base and size detection
* Value scanning: Int32, Float, String
* Narrowing scans on previous results
* Level‑1 pointer scanning and resolution
* Real‑time overlay UI (Win32 + DX11 + ImGui)

## Tech Stack

* C++17 (MSVC)
* Win32 API
* DirectX 11
* Dear ImGui

## Build

* Windows only
* Visual Studio
* Build as x64

## Usage

1. Launch the target program.
2. Run MemScanKit.
3. Enter the target executable name and click **Find**.
4. Choose a scan type, enter a value, and start scanning.

## Project Scope

This project is educational and portfolio‑oriented. It focuses on clarity, correctness, and classic low‑level techniques rather than feature bloat or evasion.

## Disclaimer

For learning and research purposes only. Use responsibly and only on software you own or have permission to analyze.
