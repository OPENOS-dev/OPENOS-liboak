# liboak — OPENOS Settings API (OAK 加密通信库)
project('liboak', 'c', default_options: ['c_std=c11'])

libsodium = dependency('libsodium')

liboak = static_library('oak',
  sources: ['liboak.c'],
  dependencies: [libsodium],
  install: true,
  install_dir: get_option('libdir'))

install_headers('liboak.h')

# 示例: 应用链接 liboak.a + -lsodium
