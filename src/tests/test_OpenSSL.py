from binascii import unhexlify
from unittest import TestCase

from OpenSSL import OpenSSL

p = unhexlify('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F')
order = unhexlify('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
zero_256bit = b'\x00' * 32

class TestOpenSSL(TestCase):
  def test_generate_random_key_pair(self):
    private_key, public_key = OpenSSL.generate_random_key_pair()
    
    #private key should be between 1 and order - 1 inclusive
    self.assertGreater(private_key, b'\x00')
    self.assertLess(private_key, order)
    
    #public key should be 0x04 || X || Y
    #both X and Y should be exactly 256 bits between 0 and p - 1 inclusive
    self.assertEqual(len(public_key), 65)
    self.assertEqual(public_key[0], 4)
    self.assertGreaterEqual(public_key[1:33], zero_256bit)
    self.assertLess(public_key[1:33], p)
    self.assertGreaterEqual(public_key[33:65], zero_256bit)
    self.assertLess(public_key[33:65], p)
