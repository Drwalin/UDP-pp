def Settings( **kwargs ):
  return {
    'flags': ['-x', 'c++', '-Wall', '-pedantic', '-Isrc', '-Isrc/ip',
    '-Isrc/ssl', '-Imbedtls/include', '-Imbedtls/include/mbedtls',
    '-Imbedtls/include/psa', '-I.', '-Imbedtls',
    '-std=c++17', '-I/usr/include', '-I/usr/include/irrlicht',
    '-I/usr/include/bullet'],
  }
