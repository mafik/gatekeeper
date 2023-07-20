'''Generates embedded.hh and embedded.cc, with contents of all the static files.'''

# Note: command for crushing png files
# pngcrush -ow -rem alla -brute -reduce static/*

import re
import fs_utils
import cc_embed
import make
import src

from pathlib import Path
from functools import partial


def slug_from_path(path):
    return re.sub(r'[^a-zA-Z0-9]', '_', str(path))


hh_path = fs_utils.generated_dir / 'embedded.hh'
cc_path = fs_utils.generated_dir / 'embedded.cc'


def gen(embedded_paths):
    with hh_path.open('w') as hh:
        print(f'''#pragma once
#include <cstddef>
#include <string_view>
#include <unordered_map>

#include "../../src/virtual_fs.hh"

namespace gatekeeper::embedded {{

extern std::unordered_map<std::string_view, VFile*> index;
''', file=hh)
        for path in embedded_paths:
            slug = slug_from_path(path)
            print(f'extern VFile {slug};', file=hh)
        print(f'''
}}  // namespace gatekeeper::embedded''', file=hh)

    with cc_path.open('w') as cc:
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
                print('\n    ' + cc_embed.bytes_to_c_string(chunk), file=cc, end='')
            print(f'''s,
}};''', file=cc)
        print(
            '''std::unordered_map<std::string_view, VFile*> index = {''', file=cc)
        for path in embedded_paths:
            slug = slug_from_path(path)
            print(f'  {{ {slug}.path, &{slug} }},', file=cc)
        print('};', file=cc)
        print('\n}  // namespace gatekeeper::embedded', file=cc)


def hook_srcs(srcs: dict[str, src.File], recipe: make.Recipe):
    paths = list(Path('static').glob('**/*'))
    paths.append(Path('gatekeeper.service'))

    # retain only files
    paths = [path for path in paths if path.is_file()]

    fs_utils.generated_dir.mkdir(exist_ok=True)

    recipe.add_step(partial(gen, paths), [hh_path, cc_path],
                    paths, desc='Embedding static files', shortcut='embedded')
    recipe.generated.add(hh_path)
    recipe.generated.add(cc_path)

    hh_file = src.File(hh_path)
    srcs[str(hh_path)] = hh_file
    cc_file = src.File(cc_path)
    srcs[str(cc_path)] = cc_file