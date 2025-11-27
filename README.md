# 🪙 FCOIN: Quantum Credstick Manager

<div align="center">

```text
   _____ ____ ___ ___ _   _ 
  |  ___/ ___/ _ \_ _| \ | |
  | |_ | |  | | | | ||  \| |
  |  _|| |__| |_| | || |\  |
  |_|   \____\___/___|_| \_|
````

[](https://python.org)
[](https://ubuntu.com)
[](https://www.google.com/search?q=)
[](https://www.google.com/search?q=)

**Advanced MIFARE Classic heuristics, auto-cracking, and payload generation.** *Developed by [Nour833](https://www.google.com/search?q=https://github.com/Nour833)*

\</div\>

-----

## 💀 The Problem: The "4-Bit ACK" Bug

If you use an **ACR122U** reader on Linux with `libnfc`, you know the pain.
When writing to MIFARE Classic cards, the card sends a tiny 4-bit acknowledgement signal. The Linux USB driver often misses this signal due to latency, causing the connection to time out before data is written.

**Writing Sector 1 on Linux is a nightmare.** **Writing Sector 1 on Android is instant.**

## ⚡ The Solution: FCOIN

**FCOIN** acts as the "Brain," and your phone acts as the "Muscle."

1.  **The Brain (Linux):** Uses the superior processing power of your PC to crack keys (`mfoc`), map the memory, detect value blocks, and calculate checksums.
2.  **The Bridge:** It generates precise, copy-pasteable payloads.
3.  **The Muscle (Android):** You input these payloads into *Mifare Classic Tool (MCT)* on your phone to bypass the USB driver bug and execute the write perfectly.

-----

## 👁️ Features

  * **🕵️‍♂️ Quantum Heuristics Engine:** Automatically detects block types:
      * **WALLETS:** Checks Little Endian integers + Inverted Checksums + Address pointers.
      * **TIMESTAMPS:** Detects Unix Timestamps (Years 2010–2035) for Parking systems.
      * **VENDORS:** Decodes ASCII and identifies vendor IDs (e.g., E-CORP).
  * **🔓 Auto-Cracking:** Wraps `mfoc` (Hardnested Attack) to recover keys from locked cards.
  * **💾 Key Persistence:** Caches cracked keys to `fcoin.keys` for instant access on subsequent runs.
  * **🧮 Smart Payload Gen:** Automatically calculates the required hex string for **Value Blocks**, including the inverted backup integrity check.
  * **🛡️ Dependency Self-Healing:** Detects missing tools and installs them automatically (via sudo).

-----

## 🛠️ Installation

### Prerequisites

  * A Linux environment (Ubuntu/Debian/Kali).
  * An NFC Reader (ACR122U, PN532, etc.).
  * An Android Phone with NFC and [Mifare Classic Tool (MCT)](https://github.com/ikarus23/MifareClassicTool).

### Setup

```bash
# 1. Clone the repository
git clone [https://github.com/Nour833/fcoin.git](https://github.com/Nour833/fcoin.git)
cd fcoin

# 2. Make the script executable
chmod +x fcoin.py

# 3. Run (Dependencies will auto-install on first run)
./fcoin.py
```

-----

## 💻 Usage

### 1\. The Analysis Phase

Connect your reader and place the target card. Run the script:

```bash
./fcoin.py
```

The script will:

1.  Crack the card keys.
2.  Display a **Memory Forensics Table**.
3.  Ask you to select a Target ID (e.g., `[0] WALLET`).
4.  Ask for the **New Balance** you want (e.g., `50.00`).

### 2\. The Injection Phase

The script will generate a **Mission Briefing** on the screen.

```text
                 >>> ANDROID MISSION BRIEFING <<<                 
          APP REQUIRED: Mifare Classic Tool (MCT)          
          ACCESS KEY:   A0A1A2A3A4A5 (Key B)           

                        PHASE 3: DATA PAYLOADS                        
 (Tap 'Open Dump Editor' or manually edit the blocks in the file)
    > Block 4: 8813000077ECFFFF8813000004FB04FB
    > Block 5: 8813000077ECFFFF8813000005FA05FA
```

1.  Open **MCT** on your phone.
2.  Use the provided **Key** to read the card.
3.  Use the **Write Block** or **Write Dump** tool to paste the payloads into the specific blocks listed by FCOIN.

-----

## 📸 Screenshots

### The Forensic Dashboard

```text
   _____ ____ ___ ___ _   _ 
  |  ___/ ___/ _ \_ _| \ | |
  | |_ | |  | | | | ||  \| |
  |  _|| |__| |_| | || |\  |
  |_|   \____\___/___|_| \_|

      [ QUANTUM CREDSTICK MANAGER ]      
              Dev: Nour833               
       "Control is an illusion."         

 [*] READER ONLINE. Waiting for target...
     Place card and press ENTER...

 [+] ACCESS GRANTED.
     Type: Mifare Classic 1k tag
     UID:  DEADBEEF

       --- [ MEMORY FORENSICS ] ---       
----------------------------------------------------------------------------------------------------
  ID  |  SEC  |     TYPE     | CONTENT PREVIEW                            |   STATUS    |    KEY A      
----------------------------------------------------------------------------------------------------
      |   0   |     MFG      | UID: DEADBEEF                              |   FACTORY   |  FFFFFFFFFFFF
 [0]  |   1   |    WALLET    | Bal: 12.50 EUR                             |   ACTIVE    |  A0A1A2A3A4A5
      |   2   |    VENDOR    | Txt: E-CORP LNDRY                          |   LOCKED    |  B0B1B2B3B4B5
      |   3   |    EMPTY     |                                            |   FACTORY   |  FFFFFFFFFFFF
```

-----

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND DIAGNOSTIC PURPOSES ONLY.**

This tool is intended for security research and managing your own hardware. The authors are not responsible for:

1.  Any damage caused to hardware (Bricked cards).
2.  Any legal consequences arising from the misuse of this tool.
3.  Lost laundry money.

**Always have permission before analyzing cards you do not own.**

-----

\<div align="center"\>

*"I wanted to save the world."*

\</div\>
