# scripts/create_test_target.py
import os
import random
import string
import shutil
import stat
from pathlib import Path

TEST_FOLDER = "test_target"
TARGET_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB

class TestEnvironmentCreator:
    def __init__(self):
        self.total_written = 0
        self.file_types = {
            "documents": [".docx", ".xlsx", ".txt", ".pdf"],
            "images": [".jpg", ".png", ".bmp"],
            "archives": [".zip", ".tar", ".gz"],
            "code": [".py", ".js", ".html"]
        }

    def _create_random_file(self, file_path, min_size_kb=1, max_size_kb=5120):
        """Create file with random content and size"""
        size = random.randint(min_size_kb, max_size_kb) * 1024  # Bytes
        content = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=size))
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        self._set_file_permissions(file_path)

    def _create_binary_file(self, file_path, size):
        """Create binary file with random content"""
        with open(file_path, 'wb') as f:
            f.write(os.urandom(size))
        self._set_file_permissions(file_path)

    def _set_file_permissions(self, path):
        """Set cross-platform write permissions"""
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # User read/write
        except Exception as e:
            print(f"Warning: Could not set permissions for {path}: {e}")

    def _create_nested_structure(self, base_dir, max_depth=3):
        """Create nested folders with large files"""
        if max_depth <= 0:
            return

        current_dir = base_dir
        for depth in range(max_depth):
            current_dir = os.path.join(current_dir, f"subfolder_{depth}")
            os.makedirs(current_dir, exist_ok=True)
            
            # Create 2-5 files per folder
            for i in range(random.randint(2, 5)):
                if self.total_written >= TARGET_SIZE:
                    return
                
                file_size = random.randint(1024, 5120) * 1024  # 1-5MB
                file_size = min(file_size, TARGET_SIZE - self.total_written)
                
                file_path = os.path.join(current_dir, f"large_file_{i}.bin")
                self._create_binary_file(file_path, file_size)
                self.total_written += file_size

    def _create_varied_files(self, base_dir):
        """Create mixed file types with random content"""
        for category, extensions in self.file_types.items():
            category_dir = os.path.join(base_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            
            # Create 10-20 files per category
            for _ in range(random.randint(10, 20)):
                if self.total_written >= TARGET_SIZE:
                    return
                
                ext = random.choice(extensions)
                filename = f"file_{''.join(random.choices(string.hexdigits, k=8))}{ext}"
                file_path = os.path.join(category_dir, filename)
                
                # Create different sized files
                max_size = 5120 if ext in [".zip", ".tar", ".gz"] else 1024
                self._create_random_file(file_path, max_size_kb=max_size)
                self.total_written += os.path.getsize(file_path)

    def _add_padding_file(self, base_dir):
        """Add final padding file if needed"""
        remaining = TARGET_SIZE - self.total_written
        if remaining > 0:
            pad_path = os.path.join(base_dir, "padding.bin")
            self._create_binary_file(pad_path, remaining)
            self.total_written += remaining
            print(f"Added padding file: {remaining/1024**2:.2f} MB")

    def _print_size_summary(self):
        """Cross-platform size formatting"""
        size_gb = self.total_written / 1024**3
        print(f"\nTest environment created at: {TEST_FOLDER}")
        print(f"Total size: {size_gb:.2f} GB")
        print(f"Total files: {sum(len(files) for _, _, files in os.walk(TEST_FOLDER))}")

    def clean_test_environment(self):
        """Remove test directory"""
        if os.path.exists(TEST_FOLDER):
            shutil.rmtree(TEST_FOLDER)
            print(f"Removed test environment: {TEST_FOLDER}")

    def create_test_environment(self):
        """Main method to create test environment"""
        self.clean_test_environment()
        
        try:
            # Create base directory
            os.makedirs(TEST_FOLDER, exist_ok=True)
            
            # Create varied file types
            self._create_varied_files(TEST_FOLDER)
            
            # Create nested binary files
            self._create_nested_structure(os.path.join(TEST_FOLDER, "binary_data"))
            
            # Add padding if needed
            self._add_padding_file(TEST_FOLDER)
            
            # Print results
            self._print_size_summary()
            
        except Exception as e:
            self.clean_test_environment()
            raise RuntimeError(f"Failed to create test environment: {e}")

if __name__ == "__main__":
    creator = TestEnvironmentCreator()
    creator.create_test_environment()