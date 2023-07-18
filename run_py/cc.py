'''Module which keeps track of all C++ sources.'''

import json
import fs_utils
import collections
import itertools
import re
import string
import functools
import os
import args
import clang
from sys import platform
from pathlib import Path
from dataclasses import dataclass
from make import Popen
from subprocess import run

CC = os.environ['CC'] = os.environ['CC'] if 'CC' in os.environ else 'clang'
CXX = os.environ['CXX'] = os.environ['CXX'] if 'CXX' in os.environ else 'clang++'
CXXFLAGS = ['-std=c++2b', '-fcolor-diagnostics',
            '-I', str(fs_utils.build_dir), '-static',
            '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections']
LDFLAGS = ['-fuse-ld=lld']

TEST_DEPS = []
TEST_LDFLAGS = []
TEST_ARGS = []

if args.verbose:
    CXXFLAGS.append('-v')

defines = set()
if platform == 'win32':
    defines.add('NOMINMAX')
    # Prefer UTF-8 over UTF-16. This means no "UNICODE" define.
    # https://learn.microsoft.com/en-us/windows/apps/design/globalizing/use-utf8-code-page
    # DO NOT ADD: defines.add('UNICODE')
    # <windows.h> has a side effect of defining ERROR macro.
    # Adding NOGDI prevents it from happening.
    defines.add('NOGDI')
    # MSVCRT <source_location> needs __cpp_consteval.
    # As of Clang 16 it's not defined by default.
    # If future Clangs add it, the manual definition can be removed.
    defines.add('__cpp_consteval')
    # Silence some MSCRT-specific deprecation warnings.
    defines.add('_CRT_SECURE_NO_WARNINGS')
    # No clue what it precisely does but many projects use it.
    defines.add('WIN32_LEAN_AND_MEAN')
    defines.add('VK_USE_PLATFORM_WIN32_KHR')
    # Set Windows version to Windows 10.
    defines.add('_WIN32_WINNT=0x0A00')
    defines.add('WINVER=0x0A00')
elif platform == 'linux':
    defines.add('VK_USE_PLATFORM_XCB_KHR')

defines.add('SK_GANESH')
defines.add('SK_VULKAN')
defines.add('SK_USE_VMA')
defines.add('SK_SHAPER_HARFBUZZ_AVAILABLE')

CXXFLAGS_RELEASE = ['-O3', '-DNDEBUG', '-flto']
CXXFLAGS_DEBUG = ['-O0', '-g']

CXXFLAGS_DEBUG += ['-D_DEBUG']
CXXFLAGS_DEBUG += ['-DSK_DEBUG']
# This subtly affects the Skia ABI and leads to crashes when passing sk_sp across the library boundary.
# For more interesting defines, check out:
# https://github.com/google/skia/blob/main/include/config/SkUserConfig.h
CXXFLAGS_DEBUG += ['-DSK_TRIVIAL_ABI=[[clang::trivial_abi]]']

CXXFLAGS += ['-D' + d for d in defines]

graph = collections.defaultdict(set)
types = dict()


def reset():
    graph.clear()
    types.clear()


binary_extension = '.exe' if platform == 'win32' else ''


def add_translation_unit(path):
    path = Path(path)  # because backslashes on Windows
    path_o = path.with_name(path.stem + '.o')
    types[str(path)] = 'translation unit'
    types[str(path_o)] = 'object file'
    depends(path_o, on=path)


def add_object(path):
    path = Path(path)
    types[str(path)] = 'object file'
    graph[str(path)]


def add_header(path):
    path = Path(path)
    types[str(path)] = 'header'

# path extension doesn't matter - can be .cc, .h, or even none at all


def add_bin(path, typ='main'):
    path = Path(path)
    path_bin = path.with_suffix(binary_extension)
    path_o = path.with_name(path.stem + '.o')
    types[str(path_bin)] = typ
    depends(path_bin, on=path_o)


def depends(what, on):
    graph[str(what)].add(str(on))


def scan(dir):
    srcs = []
    for ext in ['.cc', '.hh', '.h', '.c']:
        srcs.extend(dir.glob(f'**/*{ext}'))

    for path_abs in srcs:
        path = path_abs.relative_to(fs_utils.project_root)

        if path.suffix == '.cc' or path.suffix == '.c':
            add_translation_unit(path)
        elif path.suffix == '.h' or path.suffix == '.hh':
            add_header(path)

        if_stack = [True]
        current_defines = defines.copy() | clang.default_defines
        line_number = 0

        for line in open(path_abs, encoding='utf-8').readlines():
            line_number += 1

            # Minimal preprocessor. This allows us to skip platform-specific imports.

            # This regular experession captures most of #if defined/#ifdef variants in one go.
            # ?: at the beginning of a group means that it's non-capturing
            # ?P<...> ate the beginning of a group assigns it a name
            match = re.match(
                '^#(?P<el>el(?P<else>se)?)?(?P<end>end)?if(?P<neg1>n)?(?:def)? (?P<neg2>!)?(?:defined)?(?:\()?(?P<id>[a-zA-Z0-9_]+)(?:\))?', line)
            if match:
                test = match.group('id') in current_defines
                if match.group('neg1') or match.group('neg2'):
                    test = not test
                if match.group('else'):
                    test = not if_stack[-1]

                if match.group('end'):  # endif
                    if_stack.pop()
                elif match.group('el'):  # elif
                    if_stack[-1] = test
                else:  # if
                    if_stack.append(test)
                continue

            if not if_stack[-1]:
                continue

            # Actual scanning starts here

            match = re.match('^#include \"([a-zA-Z0-9_/\.-]+\.hh?)\"', line)
            if match:
                include = Path(match.group(1))
                dep = path.parent / include  # try relative to current source file
                if not dep.exists():
                    dep = include  # try relative to project root
                types[str(dep)] = 'header'
                depends(path, on=dep)

            match = re.match('^int main\(', line)
            if match:
                add_bin(path, 'main')

            match = re.match('^TEST(_F)?\\(', line)
            if match:
                add_bin(path, 'test')


def propagate_deps():
    binaries = [p for p, t in types.items() if t in ('test', 'main')]

    # Link object files for each header included in binaries.
    for path in binaries:
        deps = list(graph[path])
        visited = set()
        while len(deps) > 0:
            dep = deps.pop()
            if dep in visited:
                continue
            visited.add(dep)
            if types[dep] == 'header':
                object_file = dep.rsplit('.', 1)[0] + '.o'
                if object_file in graph:
                    depends(path, on=object_file)
                    deps.append(object_file)
            deps.extend(graph[dep])

    objects = [p for p, t in types.items() if t == 'object file']

    # Rebuild objects whenever any of the included header changes.
    for path in objects:
        deps = list(graph[path])
        visited = set()
        while len(deps) > 0:
            dep = deps.pop()
            if dep in visited:
                continue
            visited.add(dep)
            if types[dep] == 'header':
                depends(path, on=dep)
            deps.extend(graph[dep])


def print_debug():
    print('C++ dependency graph')
    for path in sorted(types.keys()):
        print(f' "{path}" : {types[path]}')
        for dep in sorted(graph[path]):
            print(f'  - "{dep}" : {types[dep]}')

###############
# Embedding assets
###########


byte_to_c_string_table = {c: chr(c) for c in range(32, 127)}
byte_to_c_string_table[0x00] = '\\0'
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

##############
#
##############


def AddSteps(recipe):
    # reset()
    scan(fs_utils.project_root / 'src')
    propagate_deps()

    if args.verbose:
        print_debug()

    # `graph` & `types` produced by the global scanner represent simple build graph, without accounting for build types or output paths.
    # This section duplicates some of the graph elements to account for build types & redirects their paths.

    OBJ_DIR = fs_utils.build_dir / 'obj'
    OBJ_DIR.mkdir(parents=True, exist_ok=True)

    TEST_DIR = fs_utils.build_dir / 'test'
    TEST_DIR.mkdir(parents=True, exist_ok=True)

    def redirect_path(path, path_type, build_type):
        path = Path(path)  # because backslashes on Windows
        if build_type and (path_type in ('object file', 'test', 'main')):
            path = path.with_stem(build_type + '_' + path.stem)
        name = path.name
        path = str(path)
        if path_type == 'object file':
            return str(OBJ_DIR / name)
        elif path_type == 'test':
            return str(TEST_DIR / name)
        elif path_type == 'main':
            return str(fs_utils.build_dir / name)
        elif path.startswith('generated'):
            return str(fs_utils.build_dir / path)
        else:
            return path

    redir_types = dict()
    redir_graph = dict()
    build_types = dict()
    for path, deps in graph.items():
        typ = types[path]
        if typ in ('object file', 'test', 'main'):
            build_type_list = ('', 'debug', 'release')
        else:
            build_type_list = ('',)
        for build_type in build_type_list:
            new_path = redirect_path(path, typ, build_type)
            new_deps = [redirect_path(d, types[d], build_type) for d in deps]
            redir_graph[new_path] = new_deps
            redir_types[new_path] = typ
            build_types[new_path] = build_type

    # At this point `redir_graph` & `redir_types` represent correct paths & build types.

    @dataclass
    class CompilationEntry:
        file: str
        output: str
        arguments: list

    compilation_db = []

    for path, deps in redir_graph.items():
        if path in recipe.generated:
            continue  # skip files generated by other recipes
        t = redir_types[path]
        pargs = [CXX] + CXXFLAGS
        if build_types[path] == 'debug':
            pargs += CXXFLAGS_DEBUG
        elif build_types[path] == 'release':
            pargs += CXXFLAGS_RELEASE
        if t in ('header', 'translation unit'):
            pass
        elif t == 'object file':
            recipe.generated.add(path)
            source_file = [d for d in deps if redir_types[d]
                           == 'translation unit']
            assert len(
                source_file) == 1, f'{path} has {len(source_file)} source files'
            pargs += source_file
            pargs += ['-c', '-o', path]
            if list(source_file)[0].endswith('.c') and pargs[0] == CXX:
                pargs[0] = CC
                # remove -std=c++2b from pargs
                pargs = [x for x in pargs if x != '-std=c++2b']
            builder = functools.partial(Popen, pargs)
            recipe.add_step(builder, outputs=[
                            path], inputs=deps, name=Path(path).name)
            compilation_db.append(CompilationEntry(
                source_file[0], path, pargs))
        elif t == 'test':
            binary_name = Path(path).stem
            recipe.generated.add(path)
            pargs += deps + ['-o', path] + LDFLAGS + TEST_LDFLAGS
            builder = functools.partial(Popen, pargs)
            recipe.add_step(builder, outputs=[
                            path], inputs=deps, name=f'link {binary_name}')
            runner = functools.partial(Popen, [path] + TEST_ARGS)
            recipe.add_step(runner, outputs=[], inputs=[
                            path], name=binary_name)
        elif t == 'main':
            binary_name = Path(path).stem
            recipe.generated.add(path)
            pargs += deps + ['-o', path] + LDFLAGS
            builder = functools.partial(Popen, pargs)
            recipe.add_step(builder, outputs=[
                            path], inputs=deps, name=f'link {binary_name}')
            # if platform == 'win32':
            #     MT = 'C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\mt.exe'
            #     mt_runner = functools.partial(Popen, [MT, '-manifest', 'src\win32.manifest', '-outputresource:{path}'])
            #     recipe.add_step(mt_runner, outputs=[path], inputs=[path, 'src/win32.manifest'], name=f'mt {binary_name}')
            runner = functools.partial(Popen, [f'./{path}'])
            recipe.add_step(runner, outputs=[], inputs=[
                            path], name=binary_name)
        else:
            print(
                f"File '{path}' has unknown type '{redir_types[path]}'. Dependencies:")
            for dep in deps:
                print(f'    {dep}')
            assert False

    # Shortcut recipe for running all tests (default build type)
    tests = [p for p, t in redir_types.items(
    ) if t == 'test' and not build_types[p]]
    if tests:
        # run all tests sequentially
        def run_tests(extra_args):
            for test in tests:
                run([test] + TEST_ARGS + extra_args, check=True)
        recipe.add_step(run_tests, outputs=[], inputs=tests, name='tests')

    ##########################
    # Recipe for Clang language server
    ##########################

    def compile_commands(extra_args):
        print('Generating compile_commands.json...')
        jsons = []
        for entry in compilation_db:
            arguments = ',\n    '.join(json.dumps(str(arg))
                                       for arg in entry.arguments)
            json_entry = f'''{{
  "directory": { json.dumps(str(fs_utils.project_root)) },
  "file": { json.dumps(entry.file) },
  "output": { json.dumps(entry.output) },
  "arguments": [{arguments}]
}}'''
            jsons.append(json_entry)
        with open('compile_commands.json', 'w') as f:
            print('[' + ', '.join(jsons) + ']', file=f)

    recipe.add_step(compile_commands, [
                    'compile_commands.json'], [], 'compile_commands.json')
