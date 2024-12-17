class OpenSSLError(Exception):
  def __init__(self, openssl):
    errors = []
    while True:
      e = openssl.ERR_get_error()
      if not e:
        break
      lib = openssl.ERR_lib_error_string(e)
      if lib is not None:
        lib = lib.decode()
      func = openssl.ERR_func_error_string(e)
      if func is not None:
        func = func.decode()
      reason = openssl.ERR_reason_error_string(e)
      if reason is not None:
        reason = reason.decode()
      message = '{:#08x}:{}:{}:{}'.format(e, lib, func, reason)
      errors.append((e, lib, func, reason, message))
    if not errors:
      super(OpenSSLError, self).__init__()
      return
    message = '\n'.join((err[4] for err in errors))
    super(OpenSSLError, self).__init__(message)
    e, lib, func, reason, _ = errors[0]
    self.error = e
    self.library = lib
    self.function = func
    self.reason = reason
