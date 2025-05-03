import os
import math
import json
from pathlib import Path

class RansomwareScanner:
    ENCRYPTED_EXTENSION = ".encblob"
    HIDDEN_KEY_FILE = ".hidden_ransom_key.txt"
    ENTROPY_THRESHOLD   = 7.5

    # 1. Read file then read block_size of 4096 bytes form file 
    # 2. iterate over each byte in the block_size 
    # 3. Builds a histogram (freq) where keys are byte-values and values are their counts
    # 4. dividing each byte’s count by the total number of bytes read
    # 5  calculate Shannon entropy formula where high entropy (close to 8 bits per byte) means the data is very “random”
    @staticmethod
    def file_entropy(path: Path, block_size: int = 4096) -> float:
        data = path.open('rb').read(block_size)
        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        total = len(data)
        probs = []
        for count in freq.values():
            probs.append(count / total)
            
        entropy = 0.0
        for p in probs:
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def is_suspected_ransomware_file(cls, path: Path) -> tuple[bool, str]:

        name = path.name.lower()

        # 1. encrypted-blob extension
        if name.endswith(cls.ENCRYPTED_EXTENSION):
            return True, f"encrypted extension ({cls.ENCRYPTED_EXTENSION})"

        # 2. hidden key-file extension
        if name.endswith(cls.HIDDEN_KEY_FILE):
            return True, f"hidden key extension ({cls.HIDDEN_KEY_FILE})"

        # 3 High entropy
        try:
            ent = cls.file_entropy(path)
            if ent >= cls.ENTROPY_THRESHOLD:
                return True, f"high entropy ({ent:.2f})"
        except Exception:
            pass

        return False, None

    @classmethod
    def scan_folder(cls, folder_path: str) -> list:

        flagged = []

        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                file_path = os.path.join(root, filename)

                flag, reason = cls.is_suspected_ransomware_file(Path(file_path))
                if flag:
                    flagged.append({
                        "file": file_path,
                        "indicator": reason
                    })

        return flagged

    @classmethod
    def run(cls):
        folder_input = input("Enter the directory path to scan: ").strip()
        folder_path = Path(folder_input)

        if not folder_path.is_dir():
            print(f"Error: {folder_path} is not a valid directory.")
            exit(2)

        results = cls.scan_folder(str(folder_path))  # pass as str for os.walk

        if results:
            print("Possible ransomware artifacts detected:")
            print(json.dumps(results, indent=2))
            exit(1)
        else:
            print("No obvious ransomware patterns found.")
            exit(0)


if __name__ == '__main__':
    RansomwareScanner.run()
