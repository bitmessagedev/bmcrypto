from binascii import unhexlify
from unittest import TestCase

from OpenSSL import OpenSSL

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class TestOpenSSL(TestCase):
  def test_generate_random_key_pair(self):
    private_key, public_key = OpenSSL.generate_random_key_pair()

    private_key_int = int.from_bytes(private_key)
    #private key should be between 1 and order - 1 inclusive
    self.assertGreater(private_key_int, 0)
    self.assertLess(private_key_int, order)
    
    #public key should be 0x04 || X || Y
    #both X and Y should be between 0 and p - 1 inclusive
    self.assertEqual(len(public_key), 65)
    self.assertEqual(public_key[0], 4)
    
    public_key_x = int.from_bytes(public_key[1:33])
    self.assertGreaterEqual(public_key_x, 0)
    self.assertLess(public_key_x, p)
    
    public_key_y = int.from_bytes(public_key[33:65])
    self.assertGreaterEqual(public_key_y, 0)
    self.assertLess(public_key_y, p)
