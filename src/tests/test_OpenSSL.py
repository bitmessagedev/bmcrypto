from unittest import TestCase

class TestOpenSSL(TestCase):
  def test_generate_random_key_pair(self):
    private_key, public_key = OpenSSL.generate_random_key_pair()
    self.assertEqual(len(private_key), 32)
    self.assertEqual(len(public_key), 65)
