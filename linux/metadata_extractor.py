import sys
import os
import subprocess
import platform

def ensure_pefile_installed():
    pefile_path = os.path.join(os.path.dirname(__file__), "pefile")
    sys.path.insert(0, pefile_path)
    try:
        global pefile
        import pefile
    except ImportError:
        print("[*] 'pefile' not found locally. Attempting to install it...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pefile", f"--target={pefile_path}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            sys.path.insert(0, pefile_path)
            import pefile
        except Exception:
            print("[!] Failed to install 'pefile'. Please install it manually.")
            sys.exit(1)

def check_icoutils():
    if platform.system() != "Linux":
        print("[!] icoutils auto-install only supported on Linux.")
        return
    try:
        subprocess.run(["icotool", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[*] Installing icoutils...")
        subprocess.run(["sudo", "apt", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "apt", "install", "-y", "icoutils"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_unique_filename(base_name, ext, output_dir):
    i = 0
    while True:
        suffix = f"{i}" if i > 0 else ""
        candidate = os.path.join(output_dir, f"{base_name}{suffix}{ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1

def extract_icon(exe_path, output_dir, base_name):
    subprocess.run(["wrestool", "-x", "--type=14", "-o", output_dir, exe_path], check=True)
    for f in os.listdir(output_dir):
        if f.endswith(".ico"):
            src_icon = os.path.join(output_dir, f)
            dest_icon = get_unique_filename(base_name, ".ico", output_dir)
            os.rename(src_icon, dest_icon)
            return os.path.basename(dest_icon)
    return None

def extract_version_info(exe_path):
    pe = pefile.PE(exe_path)
    version_info = {}

    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            if isinstance(fileinfo, list):
                for entry in fileinfo:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                version_info[key.decode(errors="ignore")] = value.decode(errors="ignore")
    return version_info

def generate_rc_file(icon_name, version_info, rc_path):
    with open(rc_path, 'w') as f:
        f.write(f'IDI_ICON1 ICON "{icon_name}"\n\n')
        f.write('1 VERSIONINFO\n')
        f.write('FILEVERSION {}\n'.format(
            ','.join(version_info.get("FileVersion", "0,0,0,0").split('.'))
        ))
        f.write('PRODUCTVERSION {}\n'.format(
            ','.join(version_info.get("ProductVersion", "0,0,0,0").split('.'))
        ))
        f.write('BEGIN\n')
        f.write('  BLOCK "StringFileInfo"\n')
        f.write('  BEGIN\n')
        f.write('    BLOCK "040904b0"\n')
        f.write('    BEGIN\n')
        for key, value in version_info.items():
            f.write(f'      VALUE "{key}", "{value}"\n')
        f.write('    END\n')
        f.write('  END\n')
        f.write('  BLOCK "VarFileInfo"\n')
        f.write('  BEGIN\n')
        f.write('    VALUE "Translation", 0x409, 1200\n')
        f.write('  END\n')
        f.write('END\n')

# Main logic
def main():
    ensure_pefile_installed()

    if len(sys.argv) != 2:
        print("Usage: python extract_rc.py <file.exe>")
        return

    exe_path = sys.argv[1]
    if not os.path.exists(exe_path):
        print(f"[!] File not found: {exe_path}")
        return

    base_name = os.path.splitext(os.path.basename(exe_path))[0]
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    check_icoutils()

    print("[*] Extracting icon...")
    icon_filename = extract_icon(exe_path, output_dir, base_name)
    if not icon_filename:
        print("[!] Failed to extract icon.")
        return

    print("[*] Extracting version info...")
    version_info = extract_version_info(exe_path)

    print("[*] Generating .rc file...")
    rc_path = os.path.join(output_dir, f"{base_name}.rc")
    generate_rc_file(icon_filename, version_info, rc_path)

    print(f"[+] Done! Files saved to '{output_dir}'")
    print(f"    ├── {icon_filename}")
    print(f"    └── {base_name}.rc")


if __name__ == "__main__":
    main()
