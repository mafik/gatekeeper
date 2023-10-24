'''Generates version.hh.

The version is stored in git tags. It should follow https://semver.org/.
It is retrieved using `git describe --tags` so if there are any additional
commits then it will be suffixed with a number & the abbreviated object name
of the most recent commit.

The version is stored in `.note.maf.version` section of the ELF file. It
contains a null-terminated string with the git version tag.'''

import fs_utils
import make
import src
import subprocess

hh_path = fs_utils.generated_dir / 'version.hh'
cc_path = hh_path.with_suffix('.cc')


def gen():
    version = subprocess.check_output(['git', 'describe',
                                       '--tags']).decode().strip()
    with hh_path.open('w') as hh:
        print(f'''#pragma once

namespace maf {{

struct VersionNote {{
    int namesz = 4;
    int descsz = {len(version) + 1};
    int type = 1;
    char name[4] = "MAF";
    char desc[{len(version) + 1}] = "{version}";
}};

extern const VersionNote kVersionNote;
}}''',
              file=hh)

    with cc_path.open('w') as cc:
        print(f'''#include "version.hh"

__attribute__((section(".note.maf.version"))) __attribute__((used)) const maf::VersionNote maf::kVersionNote = {{}};''',
              file=cc)


def hook_srcs(srcs: dict[str, src.File], recipe: make.Recipe):

    fs_utils.generated_dir.mkdir(exist_ok=True)

    recipe.add_step(gen, [hh_path, cc_path], [
        '.git/HEAD', '.git/refs/heads/main', 'src/version.x', 'src/version.py'
    ],
                    desc='Generating version file',
                    shortcut='version')
    recipe.generated.add(hh_path)
    recipe.generated.add(cc_path)

    hh_file = src.File(hh_path)
    hh_file.link_args[''].append('-Wl,--script=src/version.x')
    srcs[str(hh_path)] = hh_file

    cc_file = src.File(cc_path)
    srcs[str(cc_path)] = cc_file
