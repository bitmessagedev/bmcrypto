import sys
from ctypes import CDLL, POINTER, c_char, c_char_p, c_int, c_size_t, c_ulong, c_void_p
from ctypes.util import find_library
from Singleton import Singleton

__all__ = ['OpenSSLMetaclass']

class BIGNUM(c_void_p):
  pass
class BN_CTX(c_void_p):
  pass
class EC_GROUP(c_void_p):
  pass
class EC_KEY(c_void_p):
  pass
class EC_POINT(c_void_p):
  pass

_signatures = [
  #int BN_bn2bin(const BIGNUM *a, unsigned char *to)
  ('BN_bn2bin', c_int, [BIGNUM, POINTER(c_char)]),
  #void BN_CTX_free(BN_CTX *c)
  ('BN_CTX_free', None, [BN_CTX]),
  #BN_CTX *BN_CTX_secure_new(void);
  ('BN_CTX_secure_new', BN_CTX, []),
  #void EC_GROUP_clear_free(EC_GROUP *group)
  ('EC_GROUP_clear_free', None, [EC_GROUP]),
  #EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
  ('EC_GROUP_new_by_curve_name', EC_GROUP, [c_int]),
  #int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
  ('EC_GROUP_precompute_mult', c_int, [EC_GROUP, BN_CTX]),
  #void EC_KEY_free(EC_KEY *r)
  ('EC_KEY_free', None, [EC_KEY]),
  #int EC_KEY_generate_key(EC_KEY *eckey)
  ('EC_KEY_generate_key', c_int, [EC_KEY]),
  #const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key)
  ('EC_KEY_get0_private_key', BIGNUM, [EC_KEY]),
  #const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
  ('EC_KEY_get0_public_key', EC_POINT, [EC_KEY]),
  #EC_KEY *EC_KEY_new(void)
  ('EC_KEY_new', EC_KEY, []),
  #int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
  ('EC_KEY_set_group', c_int, [EC_KEY, EC_GROUP]),
  #size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx)
  ('EC_POINT_point2oct', c_size_t, [EC_GROUP, EC_POINT, c_int, c_char_p, c_size_t, BN_CTX]),
  #const char *ERR_func_error_string(unsigned long e)
  ('ERR_func_error_string', c_char_p, [c_ulong]),
  #unsigned long ERR_get_error(void)
  ('ERR_get_error', c_ulong, []),
  #const char *ERR_lib_error_string(unsigned long e)
  ('ERR_lib_error_string', c_char_p, [c_ulong]),
  #const char *ERR_reason_error_string(unsigned long e)
  ('ERR_reason_error_string', c_char_p, [c_ulong]),
  #int OBJ_sn2nid(const char *s)
  ('OBJ_sn2nid', c_int, [c_char_p])
]
def declare_functions(attr):
  names = {
    'win32': 'libcrypto-1_1-x64.dll',
    'darwin': 'crypto.46.2'
  }
  name = names.get(sys.platform, 'crypto')
  pathname = find_library(name)
  print('Found libcrypto at', pathname)
  lib = CDLL(pathname)
  for name, restype, argtypes in _signatures:
    func = getattr(lib, name)
    func.restype = restype
    func.argtypes = argtypes
    attr[name] = func

class OpenSSLMetaclass(Singleton):
  def __new__(cls, name, bases, dct):
    declare_functions(dct)
    return super(OpenSSLMetaclass, cls).__new__(cls, name, bases, dct)
