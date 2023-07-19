'''Defines what files are built.'''

from pathlib import Path
from itertools import product
import src
import fs_utils
import make
import os
import functools
import json
from args import args
from dataclasses import dataclass
from sys import platform


class ObjectFile:
    path: Path
    deps: set[src.File]
    source: src.File
    compile_args: list[str]
    build_type: str

    def __init__(self, path: Path):
        self.path = path
        self.deps = set()
        self.build_type = ''
        self.compile_args = []

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f'ObjectFile({self.path})'


class Binary:
    path: Path
    objects: list[ObjectFile]
    link_args: list[str]
    run_args: list[str]
    build_type: str

    def __init__(self, path: Path):
        self.path = path
        self.objects = []
        self.link_args = []
        self.run_args = []
        self.build_type = ''

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f'Binary({self.path}, {self.objects}, {self.link_args}, {self.run_args}, {self.build_type})'


build_type_list = ('', 'debug', 'release')

OBJ_DIR = fs_utils.build_dir / 'obj'
OBJ_DIR.mkdir(parents=True, exist_ok=True)


def obj_path(src_path: Path, build_type: str = '') -> Path:
    if build_type:
        return OBJ_DIR / (build_type + '_' + src_path.stem + '.o')
    else:
        return OBJ_DIR / (src_path.stem + '.o')


binary_extension = '.exe' if platform == 'win32' else ''


def plan(srcs) -> tuple[list[ObjectFile], list[Binary]]:

    objs: dict[str, ObjectFile] = dict()
    sources = [f for f in srcs.values() if f.is_source()]
    for src_file, build_type in product(sources, build_type_list):
        obj_file = ObjectFile(obj_path(src_file.path, build_type))
        objs[str(obj_file.path)] = obj_file
        obj_file.deps = set(src_file.transitive_includes)
        obj_file.deps.add(src_file)
        obj_file.source = src_file
        obj_file.build_type = build_type
        obj_file.compile_args += src_file.build_compile_args(build_type)
        for inc in src_file.transitive_includes:
            obj_file.compile_args += inc.build_compile_args(build_type)

    binaries: list[Binary] = []
    main_sources = [f for f in sources if f.main]
    for src_file, build_type in product(main_sources, build_type_list):
        bin_name = src_file.path.stem
        if build_type:
            bin_name = build_type + '_' + bin_name
        bin_path = fs_utils.build_dir / bin_name
        if binary_extension:
            bin_path = bin_path.with_suffix(binary_extension)
        bin_file = Binary(bin_path)
        bin_file.build_type = build_type
        binaries.append(bin_file)

        src_queue: list[src.File] = [src_file]
        visited: set[src.File] = set()
        while src_queue:
            currernt_src = src_queue.pop()
            if currernt_src in visited:
                continue
            visited.add(currernt_src)
            obj_file = objs.get(
                str(obj_path(currernt_src.path, build_type)), None)
            if obj_file:
                bin_file.objects.append(obj_file)

            for inc in currernt_src.transitive_includes:
                bin_file.link_args += inc.build_link_args(build_type)
                bin_file.run_args += inc.build_run_args(build_type)
                inc_source = srcs.get(str(inc.path.with_suffix('.cc')), None)
                if inc_source:
                    src_queue.append(inc_source)

    return list(objs.values()), binaries


compiler = os.environ['CXX'] = os.environ['CXX'] if 'CXX' in os.environ else 'clang++'

default_compile_args = ['-std=c++2b', '-fcolor-diagnostics',
                        '-I', str(fs_utils.build_dir), '-static',
                        '-ffunction-sections', '-fdata-sections']
release_compile_args = ['-O3', '-DNDEBUG', '-flto']
debug_compile_args = ['-O0', '-g', '-D_DEBUG']

default_link_args = ['-fuse-ld=lld', '-static', '-Wl,--gc-sections']
release_link_args = ['-flto']
debug_link_args = []

if args.verbose:
    default_compile_args.append('-v')


@dataclass
class CompilationEntry:
    file: str
    output: str
    arguments: list


def recipe() -> make.Recipe:
    r = make.Recipe()
    extensions = src.load_extensions()
    srcs = src.scan()
    objs, bins = plan(srcs)
    compilation_db = []
    for obj in objs:
        pargs = [compiler] + default_compile_args
        if obj.build_type == 'debug':
            pargs += debug_compile_args
        elif obj.build_type == 'release':
            pargs += release_compile_args
        pargs += obj.compile_args
        pargs += [str(obj.source.path)]
        pargs += ['-c', '-o', str(obj.path)]
        builder = functools.partial(make.Popen, pargs)
        r.add_step(builder, outputs=[obj.path],
                   inputs=obj.deps, name=obj.path.name)
        compilation_db.append(CompilationEntry(
            str(obj.source.path), str(obj.path), pargs))
    for bin in bins:
        pargs = [compiler] + default_link_args
        if bin.build_type == 'debug':
            pargs += debug_link_args
        elif bin.build_type == 'release':
            pargs += release_link_args
        pargs += [str(obj.path) for obj in bin.objects]
        pargs += bin.link_args
        pargs += ['-o', str(bin.path)]
        builder = functools.partial(make.Popen, pargs)
        r.add_step(builder, outputs=[bin.path], inputs=bin.objects,
                   name='link ' + bin.path.name)

        # if platform == 'win32':
        #     MT = 'C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\mt.exe'
        #     mt_runner = functools.partial(Popen, [MT, '-manifest', 'src\win32.manifest', '-outputresource:{path}'])
        #     r.add_step(mt_runner, outputs=[path], inputs=[path, 'src/win32.manifest'], name=f'mt {binary_name}')

        runner = functools.partial(make.Popen, [bin.path] + bin.run_args)
        r.add_step(runner, outputs=[], inputs=[bin.path], name=bin.path.name)

    for ext in extensions:
        if hasattr(ext, 'hook_final'):
            ext.hook_final(srcs, objs, bins, r)

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

    r.add_step(compile_commands, [
        'compile_commands.json'], [], 'compile_commands.json')

    return r
