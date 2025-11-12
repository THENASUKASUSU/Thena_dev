
import unittest
import os
import sys
from unittest.mock import patch
# Add the path to the script to the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from Thena_dev_v16 import secure_wipe_file, load_config

class TestSecureWipeFile(unittest.TestCase):
    def setUp(self):
        """Set up a large test file."""
        self.test_file = "large_test_file.bin"
        self.file_size = 2 * 1024 * 1024  # 2MB
        with open(self.test_file, "wb") as f:
            f.write(os.urandom(self.file_size))

        # Load the configuration to be used in the test
        self.config = load_config()

    def tearDown(self):
        """Clean up the test file if it exists."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    @patch('builtins.print')
    def test_secure_wipe_large_file(self, mock_print):
        """Test that secure_wipe_file can handle a large file without MemoryError."""
        try:
            # Pass the loaded config to the function
            secure_wipe_file(self.test_file, passes=3)
        except MemoryError:
            self.fail("secure_wipe_file raised MemoryError with a large file.")

        # Check that the file is deleted
        self.assertFalse(os.path.exists(self.test_file), "The test file was not deleted after wiping.")

if __name__ == "__main__":
    unittest.main()
