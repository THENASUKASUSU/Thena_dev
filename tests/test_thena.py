import unittest
import os
import sys
import hashlib
import zlib
import secrets
import shutil

# Add the root directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Thena_dev_v20 import (
    calculate_checksum,
    compress_data,
    decompress_data,
    obfuscate_memory,
    deobfuscate_memory,
    encrypt_file_simple,
    decrypt_file_simple,
    load_or_create_master_key,
    encrypt_file_with_master_key,
    decrypt_file_with_master_key,
    validate_password_keyfile,
    secure_wipe_file,
    config
)

class TestUtilityFunctions(unittest.TestCase):

    def test_calculate_checksum(self):
        data = b"hello world"
        expected_checksum = hashlib.sha256(data).digest()
        self.assertEqual(calculate_checksum(data), expected_checksum)

    def test_compress_decompress_data(self):
        original_data = b"some random data to compress and decompress" * 10
        compressed_data = compress_data(original_data)
        decompressed_data = decompress_data(compressed_data)
        self.assertEqual(original_data, decompressed_data)

    def test_obfuscate_deobfuscate_memory(self):
        original_data = b"some secret data to obfuscate"
        config['enable_memory_obfuscation'] = True
        config['memory_obfuscation_key'] = "a_secret_key"
        obfuscated_data = obfuscate_memory(original_data)
        deobfuscated_data = deobfuscate_memory(obfuscated_data)
        self.assertEqual(original_data, deobfuscated_data)
        self.assertNotEqual(original_data, obfuscated_data)
        config['enable_memory_obfuscation'] = False

class TestEncryptionFunctions(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_input.decrypted")
        with open(self.input_file, "wb") as f:
            f.write(secrets.token_bytes(1024))
        self.password = "test_password"
        self.keyfile = None
        config["SILENT_MODE"] = True
        config["encryption_algorithm"] = "aes-gcm"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clean up any master key file that might have been created
        if os.path.exists(config['master_key_file']):
            os.remove(config['master_key_file'])
        if os.path.exists("thena_config_v19.json"):
            os.remove("thena_config_v19.json")

    def test_encrypt_decrypt_simple(self):
        encrypt_success, _ = encrypt_file_simple(self.input_file, self.encrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)

        decrypt_success, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(decrypt_success)

        with open(self.input_file, "rb") as f:
            original_data = f.read()
        with open(self.decrypted_file, "rb") as f:
            decrypted_data = f.read()

        self.assertEqual(original_data, decrypted_data)

    def test_encrypt_decrypt_with_master_key(self):
        # This test requires the 'cryptography' package to be installed.
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.skipTest("cryptography package not installed, skipping master key test.")

        master_key = load_or_create_master_key(self.password, self.keyfile, hide_paths=True)
        self.assertIsNotNone(master_key)

        encrypt_success, _ = encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)

        decrypt_success, _ = decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(decrypt_success)

        with open(self.input_file, "rb") as f:
            original_data = f.read()
        with open(self.decrypted_file, "rb") as f:
            decrypted_data = f.read()

        self.assertEqual(original_data, decrypted_data)

    def test_decrypt_with_wrong_password(self):
        encrypt_success, _ = encrypt_file_simple(self.input_file, self.encrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)

        decrypt_success, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, "wrong_password", self.keyfile, hide_paths=True)
        self.assertFalse(decrypt_success)

    def test_decrypt_tampered_file(self):
        encrypt_success, _ = encrypt_file_simple(self.input_file, self.encrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)

        # Tamper with the encrypted file
        with open(self.encrypted_file, "r+b") as f:
            f.seek(len(f.read()) // 2) # Go to the middle of the file
            f.write(secrets.token_bytes(10))

        decrypt_success, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertFalse(decrypt_success)

class TestKDFConfigurations(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_data_kdf"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_input.decrypted")
        with open(self.input_file, "wb") as f:
            f.write(secrets.token_bytes(1024))
        self.password = "test_password"
        self.keyfile = None
        config["SILENT_MODE"] = True
        config["encryption_algorithm"] = "aes-gcm"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists("thena_config_v19.json"):
            os.remove("thena_config_v19.json")

    def test_kdf_pbkdf2(self):
        config['kdf_type'] = 'pbkdf2'
        encrypt_success, _ = encrypt_file_simple(self.input_file, self.encrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)
        decrypt_success, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(decrypt_success)
        with open(self.input_file, "rb") as f:
            original_data = f.read()
        with open(self.decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(original_data, decrypted_data)

    def test_kdf_scrypt(self):
        config['kdf_type'] = 'scrypt'
        encrypt_success, _ = encrypt_file_simple(self.input_file, self.encrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(encrypt_success)
        decrypt_success, _ = decrypt_file_simple(self.encrypted_file, self.decrypted_file, self.password, self.keyfile, hide_paths=True)
        self.assertTrue(decrypt_success)
        with open(self.input_file, "rb") as f:
            original_data = f.read()
        with open(self.decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(original_data, decrypted_data)

class TestUtilityFunctionsExtra(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_data_utils"
        os.makedirs(self.test_dir, exist_ok=True)
        self.wipe_file = os.path.join(self.test_dir, "wipe_me.txt")
        with open(self.wipe_file, "w") as f:
            f.write("some data to be wiped")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_validate_password_strength(self):
        self.assertFalse(validate_password_keyfile("short", None, interactive=False))
        self.assertFalse(validate_password_keyfile("onlylowercase", None, interactive=False))
        self.assertFalse(validate_password_keyfile("123456789012", None, interactive=False))
        self.assertTrue(validate_password_keyfile("ThisIsAStrongP@ssw0rd!", None, interactive=False))

    def test_secure_wipe_file(self):
        self.assertTrue(os.path.exists(self.wipe_file))
        secure_wipe_file(self.wipe_file, passes=1)
        self.assertFalse(os.path.exists(self.wipe_file))


class TestAsymmetricEncryption(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_data_asymmetric"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_input.decrypted")
        with open(self.input_file, "wb") as f:
            f.write(secrets.token_bytes(1024))
        self.password = "test_password"
        self.keyfile = None
        config["SILENT_MODE"] = True

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clean up key files
        for key_file in [config.get("rsa_private_key_file"), config.get("x25519_private_key_file")]:
            if key_file and os.path.exists(key_file):
                os.remove(key_file)

    def test_encrypt_decrypt_asymmetric(self):
        # Test with RSA and Curve25519 enabled
        encrypt_success, _ = encrypt_file_simple(
            self.input_file, self.encrypted_file, self.password, self.keyfile,
            hide_paths=True, use_rsa=True, use_curve25519=True
        )
        self.assertTrue(encrypt_success)

        decrypt_success, _ = decrypt_file_simple(
            self.encrypted_file, self.decrypted_file, self.password, self.keyfile,
            hide_paths=True
        )
        self.assertTrue(decrypt_success)

        with open(self.input_file, "rb") as f:
            original_data = f.read()
        with open(self.decrypted_file, "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(original_data, decrypted_data)

if __name__ == '__main__':
    unittest.main()
