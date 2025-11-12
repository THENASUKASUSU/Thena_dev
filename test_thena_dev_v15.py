import unittest
import os
import Thena_dev_v15 as Thena_dev

class TestThenaDevSimple(unittest.TestCase):
    """Tests for the simple encryption and decryption functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_encrypt_decrypt_simple(self):
        """Test the simple encryption and decryption functionality."""
        password = "Test_Password123!"
        Thena_dev.encrypt_file_simple(self.test_file, self.encrypted_file, password)
        Thena_dev.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevMasterKey(unittest.TestCase):
    """Tests for the master key encryption and decryption functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_encrypt_decrypt_master_key(self):
        """Test the master key encryption and decryption functionality."""
        password = "Test_Password123!"
        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)
        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

class TestThenaDevChaCha20(unittest.TestCase):
    """Tests for the ChaCha20-Poly1305 encryption and decryption."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_chacha.txt"
        self.encrypted_file = "test_file_chacha.txt.encrypted"
        self.decrypted_file = "test_file_chacha.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for ChaCha20-Poly1305.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_encrypt_decrypt_chacha20(self):
        """Test ChaCha20-Poly1305 encryption and decryption."""
        password = "Test_Password123!"
        # Temporarily set the encryption algorithm to chacha20-poly1305
        original_algorithm = Thena_dev.config.get("encryption_algorithm")
        Thena_dev.config["encryption_algorithm"] = "chacha20-poly1305"

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original algorithm
        Thena_dev.config["encryption_algorithm"] = original_algorithm

class TestThenaDevCompression(unittest.TestCase):
    """Tests for the compression functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_compression.txt"
        self.encrypted_file = "test_file_compression.txt.encrypted"
        self.decrypted_file = "test_file_compression.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for compression." * 1000)

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_compression_enabled(self):
        """Test encryption and decryption with compression enabled."""
        password = "Test_Password123!"
        original_compression = Thena_dev.config.get("enable_compression")
        Thena_dev.config["enable_compression"] = True

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original compression setting
        Thena_dev.config["enable_compression"] = original_compression

class TestThenaDevScrypt(unittest.TestCase):
    """Tests for the Scrypt KDF functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_scrypt.txt"
        self.encrypted_file = "test_file_scrypt.txt.encrypted"
        self.decrypted_file = "test_file_scrypt.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Scrypt.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_scrypt_kdf(self):
        """Test encryption and decryption with the Scrypt KDF."""
        password = "Test_Password123!"
        original_kdf = Thena_dev.config.get("kdf_type")
        Thena_dev.config["kdf_type"] = "scrypt"

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original KDF
        Thena_dev.config["kdf_type"] = original_kdf

class TestThenaDevPBKDF2(unittest.TestCase):
    """Tests for the PBKDF2 KDF functionality."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file_pbkdf2.txt"
        self.encrypted_file = "test_file_pbkdf2.txt.encrypted"
        self.decrypted_file = "test_file_pbkdf2.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for PBKDF2.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_pbkdf2_kdf(self):
        """Test encryption and decryption with the PBKDF2 KDF."""
        password = "Test_Password123!"
        original_kdf = Thena_dev.config.get("kdf_type")
        Thena_dev.config["kdf_type"] = "pbkdf2"

        master_key = Thena_dev.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        Thena_dev.encrypt_file_with_master_key(self.test_file, self.encrypted_file, master_key)
        Thena_dev.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

        # Restore the original KDF
        Thena_dev.config["kdf_type"] = original_kdf

class TestThenaDevCLI(unittest.TestCase):
    """Tests for the command-line interface."""

    def setUp(self):
        """Set up the test files."""
        self.test_file = "test_file.txt"
        self.encrypted_file = "test_file.txt.encrypted"
        self.decrypted_file = "test_file.txt.decrypted"
        with open(self.test_file, "w") as f:
            f.write("This is a test file for Thena_dev.py CLI.")

    def tearDown(self):
        """Tear down the test files."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.encrypted_file):
            os.remove(self.encrypted_file)
        if os.path.exists(self.decrypted_file):
            os.remove(self.decrypted_file)
        if os.path.exists(Thena_dev.config["master_key_file"]):
            os.remove(Thena_dev.config["master_key_file"])

    def test_cli_encrypt_decrypt(self):
        """Test the command-line interface."""
        password = "Cli_Test_Password1!"
        # Test encryption
        encrypt_command = [
            "python3", "Thena_dev_v15.py",
            "--encrypt",
            "-i", self.test_file,
            "-o", self.encrypted_file,
            "-p", password
        ]
        import subprocess
        result = subprocess.run(encrypt_command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Encryption failed with stderr: {result.stderr}")
        self.assertTrue(os.path.exists(self.encrypted_file))

        # Test decryption
        decrypt_command = [
            "python3", "Thena_dev_v15.py",
            "--decrypt",
            "-i", self.encrypted_file,
            "-o", self.decrypted_file,
            "-p", password
        ]
        result = subprocess.run(decrypt_command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Decryption failed with stderr: {result.stderr}")
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.decrypted_file, "r") as f:
            decrypted_content = f.read()
        with open(self.test_file, "r") as f:
            original_content = f.read()
        self.assertEqual(decrypted_content, original_content)

if __name__ == '__main__':
    unittest.main()
