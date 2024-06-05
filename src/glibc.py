import make
import build
import fs_utils
import os
import shutil
import subprocess
from functools import partial

# The purpose of this module is to set up an instance of C & C++ libraries
# that is isolated from the build OS. This allows us to control the ABI
# of the standard libraries.

# The libraries are installed in the prefix directory for the build type.

GLIBC_VERSION = '2.39'
GLIBC_STUB = f'glibc-{GLIBC_VERSION}'
GLIBC_FNAME = f'{GLIBC_STUB}.tar.xz'
GLIBC_URL = f'https://ftp.gnu.org/gnu/glibc/{GLIBC_FNAME}'
GLIBC_TAR = fs_utils.build_dir / GLIBC_FNAME
GLIBC_ROOT = fs_utils.build_dir / GLIBC_STUB

GCC_STUB = 'gcc-13.3.0'
GCC_FNAME = f'{GCC_STUB}.tar.xz'
GCC_URL = f'https://ftp.gnu.org/gnu/gcc/{GCC_STUB}/{GCC_FNAME}'
GCC_TAR = fs_utils.build_dir / GCC_FNAME
GCC_ROOT = fs_utils.build_dir / GCC_STUB

TRIPLE = build.TRIPLE

GLIBC_CONFIGURE_OPTS = [
  '--disable-default-pie',
  '--disable-profile',
  '--enable-static-ns',
  '--disable-timezone-tools',
  '--enable-bind-now',
  f'--host={TRIPLE}',
  '--disable-werror',
  '--disable-mathvec'
]

BAD_CFLAGS = ['-fcolor-diagnostics', '-flto', '-Wno-vla-extension', '--gcc-toolchain']

env = os.environ.copy()
env['CC'] = 'gcc'
env['CXX'] = 'g++'

def hook_recipe(recipe):
  # Download
  recipe.add_step(
      partial(make.Popen, ['curl', '-L', GLIBC_URL, '-o', GLIBC_TAR]),
      outputs=[GLIBC_TAR],
      inputs=[],
      desc = f'Downloading {GLIBC_STUB}',
      shortcut=f'download {GLIBC_STUB}')
  # Extract
  recipe.add_step(
      partial(make.Popen, ['tar', 'xaf', GLIBC_TAR, '-C', fs_utils.build_dir]),
      outputs=[GLIBC_ROOT],
      inputs=[GLIBC_TAR],
      desc = f'Extracting {GLIBC_STUB}',
      shortcut=f'extract {GLIBC_STUB}')

  # Download GCC
  recipe.add_step(
    partial(make.Popen, ['curl', '-L', GCC_URL, '-o', GCC_TAR]),
    outputs=[GCC_TAR],
    inputs=[],
    desc='Downloading GCC',
    shortcut='download gcc')
  
  # Extract GCC
  recipe.add_step(
    partial(make.Popen, ['tar', 'xaf', GCC_TAR, '-C', fs_utils.build_dir]),
    outputs=[GCC_ROOT],
    inputs=[GCC_TAR],
    desc='Extracting GCC',
    shortcut='extract gcc')

  for build_type in build.types:
    GLIBC_OBJDIR = GLIBC_ROOT / 'build' / build_type.name
    PREFIX = build_type.PREFIX()
    RULE_SUFFIX = build_type.rule_suffix()

    CFLAGS = build_type.CFLAGS()
    for bad_flag in BAD_CFLAGS:
      CFLAGS = list(filter(lambda x: not x.startswith(bad_flag), CFLAGS))
    CFLAGS = ' '.join(CFLAGS)


    linux_headers = ['asm', 'asm-generic', 'drm', 'linux', 'misc', 'mtd', 'rdma', 'scsi', 'sound', 'video', 'xen']
    linux_headers_outputs = [PREFIX / 'include' / x for x in linux_headers]

    def setup_linux_headers(prefix=PREFIX):
      (prefix / 'include').mkdir(parents=True, exist_ok=True)
      for header in linux_headers:
        shutil.copytree(f'/usr/include/{header}', f'{prefix / "include" / header}', dirs_exist_ok=True)

    recipe.add_step(
      setup_linux_headers,
      inputs=[],
      outputs=linux_headers_outputs,
      desc=f'Setting up Linux headers for the {build_type.name} build',
      shortcut=f'install linux-headers{RULE_SUFFIX}')

    recipe.add_step(
        partial(make.Popen, ['mkdir', '-p', GLIBC_OBJDIR]),
        outputs=[GLIBC_OBJDIR],
        inputs=[GLIBC_ROOT],
        desc=f'Making build directory {GLIBC_OBJDIR}',
        shortcut=f'mkdir {GLIBC_STUB}{RULE_SUFFIX}')
    
    recipe.add_step(
      partial(make.Popen, [(GLIBC_ROOT / 'configure').absolute(), f'CFLAGS={CFLAGS}', '--prefix', PREFIX, f'--with-headers={PREFIX}/include'] + GLIBC_CONFIGURE_OPTS, env=env, cwd=GLIBC_OBJDIR),
      inputs=[GLIBC_ROOT, GLIBC_OBJDIR] + linux_headers_outputs,
      outputs=[GLIBC_OBJDIR / 'Makefile'],
      desc=f'Configuring {GLIBC_STUB}{RULE_SUFFIX}',
      shortcut=f'configure {GLIBC_STUB}{RULE_SUFFIX}')
    
    recipe.add_step(
      partial(make.Popen, ['make', 'install'], cwd=GLIBC_OBJDIR),
      inputs=[GLIBC_OBJDIR / 'Makefile'],
      outputs=[PREFIX / 'lib' / 'libc.a', PREFIX / 'lib' / 'libc.so'],
      desc=f'Making {GLIBC_STUB}{RULE_SUFFIX}',
      shortcut=f'make {GLIBC_STUB}{RULE_SUFFIX}')
    
    GCC_OBJDIR = GCC_ROOT / 'build' / build_type.name

    recipe.add_step(
        partial(make.Popen, ['mkdir', '-p', GCC_OBJDIR]),
        outputs=[GCC_OBJDIR],
        inputs=[GCC_ROOT],
        desc=f'Making build directory for gcc{RULE_SUFFIX}',
        shortcut=f'mkdir gcc{RULE_SUFFIX}')

    def configure_gcc(prefix=PREFIX, gcc_objdir=GCC_OBJDIR):
      rpaths = [
        f'{prefix}/lib',
        # TODO: get those from /etc/ld.so.conf
        # They're needed because for some reason building GCC requires a C++ standard library
        '/usr/lib64',
        '/usr/local/lib64',
        '/usr/lib',
        '/usr/local/lib',
        '/usr/lib/gcc/x86_64-pc-linux-gnu/13/'
      ]
      LDFLAGS = ' '.join(f'-Wl,--rpath={x}' for x in rpaths)
      LDFLAGS += f' -Wl,--dynamic-linker={prefix}/lib/ld-linux-x86-64.so.2'
      LDFLAGS += ' -static-libstdc++ -static-libgcc'

      GCC_CONFIGURE_OPTS = [
          '--enable-default-ssp',
          '--enable-languages=c,c++',
          '--enable-libstdcxx-time',
          '--enable-lto',
          '--enable-threads=posix',
          '--enable-shared',
          '--enable-__cxa_atexit',
          '--disable-bootstrap',
          '--disable-cet',
          '--disable-default-pie',
          '--disable-dependency-tracking',
          '--disable-fixed-point',
          '--disable-fixincludes',
          '--disable-libada',
          '--disable-libstdcxx-pch',
          '--disable-libquadmath',
          '--disable-libsanitizer',
          '--disable-libvtv',
          '--disable-multilib',
          '--disable-nls',
          '--disable-werror',
          '--disable-valgrind-annotations',
          '--disable-vtable-verify',
          '--with-pkgversion=Automat',
          '--with-gcc-major-version-only',
          f'--with-toolexeclibdir={prefix}/lib',
          f'--with-glibc-version={GLIBC_VERSION}',
          f'--with-native-system-header-dir={prefix}/include',
          f'--with-stage1-ldflags={LDFLAGS}',
      ]

      # Put the libraries in PREFIX/lib instead of PREFIX/lib64
      subprocess.run(['sed', '-e', '/m64=/s/lib64/lib/', '-i.orig', 'gcc/config/i386/t-linux64'], cwd=GCC_ROOT)
      if not (prefix / TRIPLE).exists():
        os.symlink(f'{prefix}', f'{prefix}/{TRIPLE}')

      return make.Popen([(GCC_ROOT / 'configure').absolute(), '--prefix', prefix] + GCC_CONFIGURE_OPTS, env=env, cwd=gcc_objdir)
    
    recipe.add_step(
        configure_gcc,
        outputs=[GCC_OBJDIR / 'Makefile'],
        inputs=[GCC_ROOT, GCC_OBJDIR, PREFIX / 'lib' / 'libc.a', PREFIX / 'lib' / 'libc.so'],
        desc=f'Configuring gcc{RULE_SUFFIX}',
        shortcut=f'configure gcc{RULE_SUFFIX}')
    
    recipe.add_step(
        partial(make.Popen, ['make', '-j8'], cwd=GCC_OBJDIR),
        inputs=[GCC_OBJDIR / 'Makefile'],
        outputs=[
          GCC_OBJDIR / TRIPLE / 'libstdc++-v3' / 'src' / '.libs' / 'libstdc++.a',
          GCC_OBJDIR / TRIPLE / 'libstdc++-v3' / 'src' / '.libs' / 'libstdc++.so'],
        desc=f'Making gcc{RULE_SUFFIX}',
        shortcut=f'make gcc{RULE_SUFFIX}')
    
    recipe.add_step(
        partial(make.Popen, ['make', 'install'], cwd=GCC_OBJDIR),
        inputs=[
          GCC_OBJDIR / TRIPLE / 'libstdc++-v3' / 'src' / '.libs' / 'libstdc++.a',
          GCC_OBJDIR / TRIPLE / 'libstdc++-v3' / 'src' / '.libs' / 'libstdc++.so'],
        outputs=[
          PREFIX / 'lib' / 'libstdc++.a',
          PREFIX / 'lib' / 'libstdc++.so'],
        desc=f'Installing gcc{RULE_SUFFIX}',
        shortcut=f'gcc{RULE_SUFFIX}')
