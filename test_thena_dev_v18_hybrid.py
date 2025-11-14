import unittest
import os
import sys
import shutil
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import Thena_dev_v18 as thena

class TestThenaHybrid(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        self.input_file = os.path.join(self.test_dir, "test_input.txt")
        self.encrypted_file = os.path.join(self.test_dir, "test_input.txt.encrypted")
        self.decrypted_file = os.path.join(self.test_dir, "test_output.txt")
        self.password = "test_password"
        self.keyfile = "test.keyfile"

        with open(self.input_file, "w") as f:
            f.write("This is a test file for Thena_dev_v18 hybrid encryption.")
        with open(self.keyfile, "w") as f:
            f.write("keyfile content")

        # Patch config for testing
        test_config = {
            "rsa_key_size": 2048,  # Use smaller key size for faster tests
            "argon2_time_cost": 1,
            "master_key_file": ".master_key_encrypted_v18",
        }
        self.config_patcher = patch.dict(thena.config, test_config)
        self.config_patcher.start()

    def tearDown(self):
        self.config_patcher.stop()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for file in [self.keyfile, "rsa_private_key_v18.pem", "x25519_private_key_v18.pem", ".master_key_encrypted_v18"]:
            if os.path.exists(file):
                os.remove(file)

    def test_key_generation_and_loading(self):
        rsa_priv, x25519_priv = thena.generate_and_save_keys(self.password, self.keyfile)
        self.assertIsNotNone(rsa_priv)
        self.assertIsNotNone(x25519_priv)

        loaded_rsa, loaded_x25519 = thena.load_keys(self.password, self.keyfile)
        self.assertIsNotNone(loaded_rsa)
        self.assertIsNotNone(loaded_x25519)

    def test_hybrid_encryption_decryption_success(self):
        rsa_priv, x25519_priv = thena.generate_and_save_keys(self.password, self.keyfile)

        thena.encrypt_file_hybrid(self.input_file, self.encrypted_file, rsa_priv, x25519_priv)
        self.assertTrue(os.path.exists(self.encrypted_file))

        thena.decrypt_file_hybrid(self.encrypted_file, self.decrypted_file, rsa_priv.public_key(), x25519_priv)
        self.assertTrue(os.path.exists(self.decrypted_file))

        with open(self.input_file, "r") as f_in, open(self.decrypted_file, "r") as f_out:
            self.assertEqual(f_in.read(), f_out.read())

    def test_hybrid_decryption_wrong_key(self):
        rsa_priv, x25519_priv = thena.generate_and_save_keys(self.password, self.keyfile)
        thena.encrypt_file_hybrid(self.input_file, self.encrypted_file, rsa_priv, x25519_priv)

        # Generate a new set of keys
        wrong_rsa, wrong_x25519 = thena.generate_and_save_keys("wrong_password", self.keyfile)

        with self.assertRaises(ValueError):
            thena.decrypt_file_hybrid(self.encrypted_file, self.decrypted_file, wrong_rsa.public_key(), wrong_x25519)

if __name__ == "__main__":
    unittest.main()
