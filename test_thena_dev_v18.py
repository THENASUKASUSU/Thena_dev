import unittest
import os
import sys
import shutil
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import rsa, x25519

# Add the path to the script to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the module to be tested
import Thena_dev_v18 as thena

class TestThenaDev(unittest.TestCase):
    """Test suite for the Thena_dev_v18 encryption script."""

    def setUp(self):
        """Set up the test environment before each test."""
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.txt.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_output.txt")

        # Consistent file names for keys
        self.master_key_file = ".master_key_encrypted_v18_test"
        self.rsa_key_file = "rsa_private_key_v18_test.pem"
        self.x25519_key_file = "x25519_private_key_v18_test.pem"

        with open(self.input_file, "w") as f:
            f.write("This is a test file for Thena_dev_v18.")

        # Load the default config from the script and then override for tests
        test_config = thena.load_config()
        test_config.update({
            "argon2_time_cost": 1,
            "scrypt_n": 2**4,
            "pbkdf2_iterations": 10,
            "master_key_file": self.master_key_file,
            "rsa_private_key_file": self.rsa_key_file,
            "x25519_private_key_file": self.x25519_key_file,
            "encryption_algorithm": "aes-gcm", # Default to legacy for old tests
            "enable_decoy_blocks": False,
        })

        self.config_patcher = patch.dict(thena.config, test_config, clear=True)
        self.config_patcher.start()

    def tearDown(self):
        """Clean up the test environment after each test."""
        self.config_patcher.stop()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        # Clean up all possible generated files
        for file_path in [
            self.master_key_file, self.rsa_key_file, self.x25519_key_file,
            "test.keyfile", "wrong.keyfile", "thena_config_v18.json"
        ]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass

    @patch('builtins.input', return_value='y')
    def test_simple_encryption_decryption_success(self, mock_input):
        """Test successful encryption and decryption in simple mode (AES-GCM)."""
        thena.config['encryption_algorithm'] = 'aes-gcm'
        password = "test_password"

        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Simple encryption failed.")
        self.assertTrue(os.path.exists(self.encrypted_file))

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Simple decryption failed.")
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read())

    @patch('builtins.input', return_value='y')
    def test_simple_decryption_wrong_password(self, mock_input):
        """Test simple decryption fails with the wrong password (AES-GCM)."""
        thena.config['encryption_algorithm'] = 'aes-gcm'
        password = "test_password"
        wrong_password = "wrong_password"

        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc)

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, wrong_password)
        self.assertFalse(success_dec)
        self.assertFalse(os.path.exists(self.decrypted_file))

    @patch('builtins.input', return_value='y')
    def test_master_key_encryption_decryption_success(self, mock_input):
        """Test successful encryption and decryption with a master key (AES-GCM)."""
        thena.config['encryption_algorithm'] = 'aes-gcm'
        password = "test_password"

        master_key = thena.load_or_create_master_key(password, None)
        self.assertIsNotNone(master_key)

        success_enc, _ = thena.encrypt_file_with_master_key(self.input_file, self.encrypted_file, master_key)
        self.assertTrue(success_enc)

        success_dec, _ = thena.decrypt_file_with_master_key(self.encrypted_file, self.decrypted_file, master_key)
        self.assertTrue(success_dec)

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read())

    def test_hybrid_encryption_decryption_success(self):
        """Test successful encryption and decryption using the hybrid scheme."""
        thena.config['encryption_algorithm'] = 'hybrid-rsa-x25519'
        password = "a_very_strong_password_for_hybrid_test_123!@#"

        rsa_priv, x25519_priv = thena.generate_and_save_keys(password, None)
        self.assertTrue(os.path.exists(self.rsa_key_file))
        self.assertTrue(os.path.exists(self.x25519_key_file))

        thena.encrypt_file_hybrid(self.input_file, self.encrypted_file, rsa_priv, x25519_priv)
        self.assertTrue(os.path.exists(self.encrypted_file))

        rsa_pub = rsa_priv.public_key()
        thena.decrypt_file_hybrid(self.encrypted_file, self.decrypted_file, rsa_pub, x25519_priv)
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read())

    @patch('sys.exit')
    @patch('Thena_dev_v18.validate_password_keyfile', return_value=True)
    @patch('Thena_dev_v18.load_keys', return_value=(MagicMock(), MagicMock()))
    @patch('Thena_dev_v18.encrypt_file_hybrid')
    def test_main_encrypt_cli_hybrid(self, mock_encrypt_hybrid, mock_load_keys, mock_validate, mock_exit):
        """Test the CLI for hybrid encryption."""
        thena.config['encryption_algorithm'] = 'hybrid-rsa-x25519'
        argv = ['Thena_dev_v18.py', '--encrypt', '-i', self.input_file, '-o', self.encrypted_file, '-p', 'password']
        with patch('sys.argv', argv):
            thena.main()
            mock_load_keys.assert_called_with('password', None)
            mock_encrypt_hybrid.assert_called()

    @patch('sys.exit')
    @patch('Thena_dev_v18.validate_password_keyfile', return_value=True)
    @patch('Thena_dev_v18.decrypt_file_hybrid')
    def test_main_decrypt_cli_hybrid(self, mock_decrypt_hybrid, mock_validate, mock_exit):
        """Test the CLI for hybrid decryption."""
        thena.config['encryption_algorithm'] = 'hybrid-rsa-x25519'
        password = "a_very_strong_password_for_hybrid_test_123!@#"

        # Create real keys for the load_keys function to succeed
        thena.generate_and_save_keys(password, None)
        self.assertTrue(os.path.exists(self.rsa_key_file))

        with open(self.encrypted_file, 'wb') as f:
            f.write(b"dummy_encrypted_data")

        argv = ['Thena_dev_v18.py', '--decrypt', '-i', self.encrypted_file, '-o', self.decrypted_file, '-p', password]
        with patch('sys.argv', argv):
            thena.main()
            mock_decrypt_hybrid.assert_called()

    @patch('builtins.input', return_value='y')
    def test_decoy_blocks_feature(self, mock_input):
        """Test that decoy blocks are added and ignored correctly (AES-GCM)."""
        thena.config['encryption_algorithm'] = 'aes-gcm'
        thena.config['enable_decoy_blocks'] = True
        thena.config['decoy_block_count'] = 3
        thena.config['decoy_block_max_size'] = 128

        password = "test_password"
        original_size = os.path.getsize(self.input_file)

        success_enc, _ = thena.encrypt_file_simple(self.input_file, self.encrypted_file, password)
        self.assertTrue(success_enc, "Encryption with decoy blocks failed.")

        encrypted_size = os.path.getsize(self.encrypted_file)
        self.assertTrue(encrypted_size > original_size, "Encrypted file with decoys is not larger.")

        success_dec, _ = thena.decrypt_file_simple(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(success_dec, "Decryption with decoy blocks failed.")

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read())

if __name__ == "__main__":
    unittest.main()