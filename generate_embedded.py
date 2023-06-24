#!/usr/bin/env python3

import itertools
import re
import string

from pathlib import Path
from datetime import datetime, timezone

embedded_paths = list(Path('static').glob('**/*'))
embedded_paths.append(Path('gatekeeper.service'))

# retain only files
embedded_paths = [path for path in embedded_paths if path.is_file()]

Path('generated').mkdir(exist_ok=True)


def slug_from_path(path):
    return re.sub(r'[^a-zA-Z0-9]', '_', str(path))


with Path('generated/embedded.hh').open('w') as hh:
    print(f'''#pragma once
#include <cstddef>
#include <string_view>
#include <unordered_map>

#include "../src/virtual_fs.hh"

namespace gatekeeper::embedded {{

extern std::unordered_map<std::string_view, VFile*> index;
''', file=hh)
    for path in embedded_paths:
        slug = slug_from_path(path)
        print(f'extern VFile {slug};', file=hh)
    print(f'''
}}  // namespace gatekeeper::embedded''', file=hh)

byte_to_c_string_table = {c: chr(c) for c in range(32, 127)}
byte_to_c_string_table[0x22] = '\\"'
byte_to_c_string_table[0x5c] = '\\\\'
byte_to_c_string_table[0x07] = '\\a'
byte_to_c_string_table[0x08] = '\\b'
byte_to_c_string_table[0x0c] = '\\f'
byte_to_c_string_table[0x0a] = '\\n'
byte_to_c_string_table[0x0d] = '\\r'
byte_to_c_string_table[0x09] = '\\t'
byte_to_c_string_table[0x0b] = '\\v'

digit_bytes = set(ord(c) for c in string.digits)


def byte_to_c_string(b, next_b=None):
    if b in byte_to_c_string_table:
        return byte_to_c_string_table[b]
    elif next_b in digit_bytes:
        return '\\' + format(b, '03o')
    else:
        return '\\' + format(b, 'o')


def c_string_from_bytes(bytes):
    # x is a dummy byte
    return '"' + ''.join(byte_to_c_string(b, next_b) for b, next_b in itertools.pairwise(bytes + b'x')) + '"'


with Path('generated/embedded.cc').open('w') as cc:
    print(f'''#include "embedded.hh"

using namespace std::string_literals;

namespace gatekeeper::embedded {{''', file=cc)
    for path in embedded_paths:
        slug = slug_from_path(path)
        print(f'''
VFile {slug} = {{
  .path = "{path}"s,
  .content = ''', file=cc, end='')
        buf = path.read_bytes()
        bytes_per_line = 200
        for i in range(0, len(buf), bytes_per_line):
            chunk = buf[i:i+bytes_per_line]
            print('\n    ' + c_string_from_bytes(chunk), file=cc, end='')
        print(f'''s,
}};''', file=cc)
    print(
        '''std::unordered_map<std::string_view, VFile*> index = {''', file=cc)
    for path in embedded_paths:
        slug = slug_from_path(path)
        print(f'  {{ {slug}.path, &{slug} }},', file=cc)
    print('};', file=cc)
    print('\n}  // namespace gatekeeper::embedded', file=cc)
