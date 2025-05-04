import os
import math
import json
import subprocess
from pathlib import Path
import pefile
import yara

class RansomwareScanner:
    ENCRYPTED_EXTENSION = ".encblob"
    HIDDEN_KEY_FILE = ".hidden_ransom_key.txt"
    ENTROPY_THRESHOLD = 7.5
    SUSPICIOUS_EXTENSIONS = [".fun", ".dog", ".wcry", ".locked", ".payforunlock"]
    SUSPICIOUS_DLLS = [
        "advapi32.dll", "bcrypt.dll", "ncrypt.dll", "crypt32.dll",
        "wininet.dll", "ws2_32.dll", "urlmon.dll", "kernel32.dll"
    ]
    SUSPICIOUS_FUNCTIONS = [
        "CryptEncrypt", "CryptDecrypt", "CreateFile", "WriteFile",
        "DeleteFile", "InternetOpen", "HttpSendRequest", "LoadLibrary",
        "GetProcAddress", "FindFirstFile", "FindNextFile"
    ]
    SUSPICIOUS_STRINGS = [
        "encrypted", "pay", "delete", "key", "ransom", "decrypt",
        "vssadmin delete shadows", "cipher /w", "bcdedit /set"
    ]
    YARA_RULES = """
    rule RansomwareDetection {
        strings:
            $ransom_note = "encrypted"
            $delete_shadow = "vssadmin delete shadows"
            $cipher_command = "cipher /w"
        condition:
            any of them
    }
    """

    @staticmethod
    def file_entropy(path: Path, block_size: int = 4096) -> float:
        data = path.open('rb').read(block_size)
        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        total = len(data)
        probs = [count / total for count in freq.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        return entropy

    @classmethod
    def is_suspected_ransomware_file(cls, path: Path) -> tuple[bool, str]:
        name = path.name.lower()

        if name.endswith(cls.ENCRYPTED_EXTENSION):
            return True, f"encrypted extension ({cls.ENCRYPTED_EXTENSION})"

        if name.endswith(cls.HIDDEN_KEY_FILE):
            return True, f"hidden key extension ({cls.HIDDEN_KEY_FILE})"

        if any(name.endswith(ext) for ext in cls.SUSPICIOUS_EXTENSIONS):
            return True, f"suspicious extension ({name})"

        try:
            ent = cls.file_entropy(path)
            if ent >= cls.ENTROPY_THRESHOLD:
                return True, f"high entropy ({ent:.2f})"
        except Exception:
            pass

        return False, None

    @staticmethod
    def analyze_executable(file_path: str) -> list:
        findings = []
        try:
            # Analyze imports and functions using pefile
            pe = pefile.PE(file_path)
            imported_dlls = [entry.dll.decode().lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]
            for dll in RansomwareScanner.SUSPICIOUS_DLLS:
                if dll in imported_dlls:
                    findings.append(f"Suspicious DLL imported: {dll}")

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in RansomwareScanner.SUSPICIOUS_FUNCTIONS:
                        findings.append(f"Suspicious function used: {imp.name.decode()}")

            # Check for unusual section names
            known_sections = {".text", ".rdata", ".edata", ".tls", ".data", ".rodata", ".rsrc", ".pdata", ".bss", ".idata", ".reloc", ".CRT"}
            for section in pe.sections:
                section_name = section.Name.decode().strip('\x00').lower()
                if section_name not in known_sections:
                    findings.append(f"Unusual section name: {section_name}")
        except Exception as e:
            findings.append(f"Error analyzing executable: {e}")

        try:
            # Extract static strings using subprocess
            output = subprocess.check_output(["strings", file_path])
            strings = output.decode().splitlines()
            for string in strings:
                if any(keyword in string.lower() for keyword in RansomwareScanner.SUSPICIOUS_STRINGS):
                    findings.append(f"Suspicious string found: {string}")
        except Exception as e:
            findings.append(f"Error extracting strings: {e}")

        return findings

    @staticmethod
    def yara_scan(file_path: str) -> list:
        findings = []
        try:
            rules = yara.compile(source=RansomwareScanner.YARA_RULES)
            matches = rules.match(file_path)
            for match in matches:
                findings.append(f"YARA rule matched: {match.rule}")
        except Exception as e:
            findings.append(f"Error running YARA scan: {e}")
        return findings

    @classmethod
    def scan_folder(cls, folder_path: str) -> list:
        flagged = []
        total_files = 0
        flagged_files = 0

        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                total_files += 1
                file_path = os.path.join(root, filename)
                flag, reason = cls.is_suspected_ransomware_file(Path(file_path))
                if flag:
                    flagged_files += 1
                    flagged.append({
                        "file": file_path,
                        "indicator": reason
                    })

                # Analyze executables
                if filename.endswith(".exe"):
                    findings = cls.analyze_executable(file_path)
                    yara_findings = cls.yara_scan(file_path)
                    findings.extend(yara_findings)
                    if findings:
                        flagged_files += 1
                        flagged.append({
                            "file": file_path,
                            "indicator": findings
                        })

        print(f"Scanned {total_files} files. Flagged {flagged_files} as suspicious.")
        return flagged

    @classmethod
    def run(cls):
        folder_input = input("Enter the directory path to scan: ").strip()
        folder_path = Path(folder_input)

        if not folder_path.is_dir():
            print(f"Error: {folder_path} is not a valid directory.")
            exit(2)

        print("Scanning folder for ransomware patterns...")
        results = cls.scan_folder(str(folder_path))

        if results:
            print("Possible ransomware artifacts detected:")
            print(json.dumps(results, indent=2))
            print(f"Found {len(results)} threats.")
            exit(1)
        else:
            print("No obvious ransomware patterns found.")
            exit(0)


if __name__ == '__main__':
    RansomwareScanner.run()