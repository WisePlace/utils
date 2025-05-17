import sys
import os
import subprocess
import platform
import tempfile

def ensure_pefile_installed():
    try:
        global pefile
        import pefile
    except ImportError:
        print("[*] 'pefile' not found. Attempting to install it...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pefile"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            import pefile
        except Exception:
            print("[!] Failed to install 'pefile'. Please install it manually: pip install pefile")
            sys.exit(1)

def ensure_pillow_installed():
    try:
        global Image
        from PIL import Image
    except ImportError:
        print("[*] 'Pillow' not found. Attempting to install it...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "Pillow"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            from PIL import Image
        except Exception:
            print("[!] Failed to install 'Pillow'. Please install it manually: pip install Pillow")
            sys.exit(1)
            
def check_icoutils():
    if platform.system() != "Linux":
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
    if platform.system() == "Windows":
        try:
            import win32api
            import win32con
            import win32gui
            import win32ui
        except ImportError:
            print("[*] 'pywin32' not found. Attempting to install it...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "pywin32"], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                import win32api
                import win32con
                import win32gui
                import win32ui
            except Exception:
                print("[!] Failed to install 'pywin32'. Please install it manually: pip install pywin32")
                sys.exit(1)

        try:
            from PIL import Image
        except ImportError:
            print("[*] 'Pillow' not found. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", "Pillow"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            from PIL import Image

        large, small = win32gui.ExtractIconEx(exe_path, 0)
        if not large:
            print("[!] No icon found in the executable.")
            return None

        icon_path = get_unique_filename(base_name, ".ico", output_dir)

        ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_x)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)

        icon_handle = large[0].Handle if hasattr(large[0], "Handle") else large[0]
        win32gui.DrawIconEx(hdc.GetHandleOutput(), 0, 0, icon_handle, ico_x, ico_x, 0, None, win32con.DI_NORMAL)

        temp_bmp = os.path.join(tempfile.gettempdir(), "temp_icon.bmp")
        hbmp.SaveBitmapFile(hdc, temp_bmp)

        img = Image.open(temp_bmp).convert("RGBA")
        icon_path = get_unique_filename(base_name, ".ico", output_dir)

        icon_sizes = [16, 24, 32, 48, 64, 128, 256]
        img.save(icon_path, format='ICO', sizes=[(s, s) for s in icon_sizes])
        return os.path.basename(icon_path)

    else:
        try:
            result = subprocess.run(
                ["wrestool", "-x", "--type=14", "-o", output_dir, exe_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print("[!] wrestool failed:")
            print(e.stderr.decode())
            return None
        
        found_icon = False
        for f in os.listdir(output_dir):
            if f.lower().endswith(".ico"):
                src_icon = os.path.join(output_dir, f)
                dest_icon = get_unique_filename(base_name, ".ico", output_dir)
                try:
                    os.rename(src_icon, dest_icon)
                    return os.path.basename(dest_icon)
                except Exception as e:
                    print(f"[!] Failed to rename extracted icon: {e}")
                    return None
        if not found_icon:
            print("[!] No .ico file found in the target.")
        return None

def extract_version_info(exe_path):
    try:
        pe = pefile.PE(exe_path)
    except pefile.PEFormatError:
        print("{exe_path} is not a valid PE file.")
        return {}
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

def main():
    ensure_pefile_installed()
    ensure_pillow_installed()
    
    if len(sys.argv) != 2:
        print("Usage: python metadata_extractor.py <file.exe>")
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
