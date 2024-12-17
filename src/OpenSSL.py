from ctypes import create_string_buffer
from OpenSSLError import OpenSSLError
from OpenSSLMetaclass import OpenSSLMetaclass

class OpenSSL(object, metaclass=OpenSSLMetaclass):
  def __init__(self):
    super(OpenSSL, self).__init__()
    self.bn_ctx = self.BN_CTX_secure_new()
    self.EC_GROUP_new_secp256k1()
  
  def __del__(self):
    self.BN_CTX_free(getattr(self, 'bn_ctx', None))
    self.EC_GROUP_clear_free(getattr(self, 'group', None))
  
  def EC_GROUP_new_secp256k1(self):
    nid = self.OBJ_sn2nid(b'secp256k1')
    group = None
    if nid:
      group = self.EC_GROUP_new_by_curve_name(nid)
    if not group:
      #TODO: Define the curve here instead of raising an exception
      raise Exception('secp256k1 not defined')
    self.group = group

  def generate_random_key_pair(self):
    group = self.group
    key = None
    try:
      key = self.EC_KEY_new()
      if not key:
        raise OpenSSLError()
      
      ok = self.EC_KEY_set_group(key, group)
      if not ok:
        raise OpenSSLError()
      
      ok = self.EC_KEY_generate_key(key)
      if not ok:
        raise OpenSSLError()
      
      private_key = self.EC_KEY_get0_private_key(key)
      public_key = self.EC_KEY_get0_public_key(key)
      buf = create_string_buffer(65)
      
      size = self.BN_bn2bin(private_key, buf)
      if not size:
        raise OpenSSLError()
      raw_private_key = buf.raw[:size]
      
      size = self.EC_POINT_point2oct(group, public_key, 4, buf, len(buf), self.bn_ctx)
      if size < 0:
        raise OpenSSLError()
      raw_public_key = buf.raw[:size]
      
      return raw_private_key, raw_public_key
    finally:
      self.EC_KEY_free(key)

OpenSSL = OpenSSL()
