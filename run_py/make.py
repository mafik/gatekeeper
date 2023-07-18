'''Pythonic replacement for GNU Make.'''

from pathlib import Path
from collections import defaultdict
from sys import platform
import time
import multiprocessing
import os
import subprocess
import signal
import shutil
import tempfile
import hashlib
import fs_utils

HASH_DIR = fs_utils.build_dir / 'hashes'
HASH_DIR.mkdir(parents=True, exist_ok=True)


def Popen(args, extra_args=[], **kwargs):
    '''Wrapper around subprocess.Popen which captures STDERR into a temporary file.'''
    f = tempfile.TemporaryFile()
    str_args = [str(x) for x in args + extra_args]
    p = subprocess.Popen(str_args, stderr=f, **kwargs)
    p.stderr = f
    return p


def hexdigest(path):
    path = Path(path)
    if path.exists():
        if path.is_dir():
            contents = path.stat().st_mtime_ns.to_bytes(8, 'big')
        else:
            contents = path.read_bytes()
    else:
        contents = b''
    return hashlib.md5(contents).hexdigest()


class Step:
    def __init__(self, name, outputs, inputs, build, id, stderr_prettifier):
        self.name = name
        self.outputs = set(str(x) for x in outputs)
        self.inputs = set(str(x) for x in inputs)
        self.build = build  # function that executes this step
        self.builder = None  # Popen instance while this step is being built
        self.id = id
        self.stderr_prettifier = stderr_prettifier
        self.extra_args = []

    def __repr__(self):
        return f'{self.name}'

    def build_and_log(self, reasons):
        print('Building', self.name)  # , '(because', *reasons, 'changed)')
        return self.build(extra_args=self.extra_args)

    def record_input_hashes(self):
        hash_path = HASH_DIR / self.name
        text = '\n'.join(f'{inp} {hexdigest(inp)}' for inp in self.inputs)
        hash_path.write_text(text)

    def dirty_inputs(self):
        # Check 1: If the output doesn't exist, report that all inputs have changed.
        for out in self.outputs:
            if not Path(out).exists():
                return self.inputs

        # Check 2: Check whether the inputs are older than outputs.
        if self.outputs:
            build_time = min(Path(t).stat().st_mtime if Path(
                t).exists() else 0 for t in self.outputs)
        else:
            build_time = 0
        updated_inputs = []
        for inp in self.inputs:
            p = Path(inp)
            if p.exists() and p.stat().st_mtime < build_time:
                continue
            if not p.exists():
                continue
            updated_inputs.append(inp)

        if len(updated_inputs) == 0:
            return []

        # Check 3: If possible - check whether the contents have changed.
        hash_path = HASH_DIR / self.name
        if not hash_path.exists():
            return updated_inputs
        recorded_hashes = defaultdict(str)
        for line in hash_path.open().readlines():
            inp, hsh = line.split()
            recorded_hashes[inp] = hsh
        changed_inputs = [inp for inp in updated_inputs if hexdigest(
            inp) != recorded_hashes[inp]]
        return changed_inputs

    def is_dirty(self):
        return len(self.dirty_inputs()) > 0

    def build_if_needed(self):
        if len(self.inputs) == 0 and any(not Path(out).exists() for out in self.outputs):
            return self.build_and_log([])
        updated_inputs = self.dirty_inputs()
        if len(updated_inputs) > 0:
            return self.build_and_log(updated_inputs)
        if len(self.outputs) == 0:
            return self.build_and_log([])


class Recipe:
    def __init__(self):
        '''A list of steps that should be taken in order to build the final product.'''
        self.steps = []
        '''A set of files that have been automatically generated and can be safely removed.'''
        self.generated = set()
        '''Maps PID of a running process to a step.'''
        self.pid_to_step = dict()

    def clean(self):
        '''Removes all of the generated files.'''
        for p in self.generated:
            p = Path(p)
            if p.exists():
                if p.is_file() or p.is_symlink():
                    print(f'  > unlink {p}')
                    p.unlink()
                else:
                    print(f'  > rmtree {p}')
                    shutil.rmtree(p)

    def is_dirty(self):
        '''Returns True if the recipe needs to be built.'''
        return any(s.is_dirty() for s in self.steps)

    def add_step(self, build_func, outputs, inputs, name=None, stderr_prettifier=lambda x: x):
        if not name:
            name = build_func.__name__
        self.steps.append(Step(name, outputs, inputs, build_func,
                          len(self.steps), stderr_prettifier))

    # prunes the list of steps and only leaves the steps that are required for some target
    def set_target(self, target):
        out_index = dict()
        target_step = None
        for step in self.steps:
            if step.name == target:
                target_step = step
            for output in step.outputs:
                out_index[output] = step

        if target_step == None:
            from difflib import get_close_matches
            close = get_close_matches(target, [s.name for s in self.steps])
            if close:
                close = ', '.join(close)
                raise Exception(
                    f'{target} is not a valid target. Close matches: {close}.')
            else:
                possible = ', '.join([s.name for s in self.steps])
                raise Exception(
                    f'{target} is not a valid target. Possible matches: {possible}.')

        new_steps = set()
        q = [target_step]
        while q:
            step = q.pop()
            new_steps.add(step)
            for input in step.inputs:
                if input in out_index:
                    dep = out_index[input]
                    q.append(dep)
                elif not Path(input).exists():
                    raise Exception(
                        f'Step "{step.name}" requires `{input}` but it doesn\'t exist and there is no recipe to build it.')
        new_steps = list(new_steps)
        new_steps.sort(key=self.steps.index)

        self.steps = new_steps

    def execute(self, watcher):
        start_time = time.time()
        desired_parallelism = multiprocessing.cpu_count()
        ready_steps = []

        for step in self.steps:
            step.blocker_count = 0

        for a in self.steps:
            for b in self.steps:
                if b.outputs & a.inputs:
                    a.blocker_count += 1
            if a.blocker_count == 0:
                ready_steps.append(a)

        def on_step_finished(a):
            a.record_input_hashes()
            for b in self.steps:
                if b.inputs & a.outputs:
                    b.blocker_count -= 1
                    if b.blocker_count == 0:
                        ready_steps.append(b)

        def check_for_pid():
            for pid, step in self.pid_to_step.items():
                status = step.builder.poll()
                if status != None:
                    return pid, status
            status = watcher.poll()
            if status != None:
                return watcher.pid, status
            return 0, 0

        def wait_for_pid():
            if platform == 'win32':
                while True:
                    pid, status = check_for_pid()
                    if pid:
                        return pid, status
                    time.sleep(0.01)
            else:
                return os.wait()

        while ready_steps or self.pid_to_step:
            if len(ready_steps) == 0 or len(self.pid_to_step) >= desired_parallelism:
                running_names = ', '.join(
                    [r.name for r in self.pid_to_step.values()])
                print(
                    f'Waiting for one of {len(self.pid_to_step)} running steps ({running_names})...')
                pid, status = wait_for_pid()
                if pid == watcher.pid:
                    self.interrupt()
                    print(
                        'Sources have been modified. Interrupting the build process...')
                    return False
                step = self.pid_to_step[pid]
                if status:
                    print(f'Recipe for {step.name} finished with an error:\n')
                    if hasattr(step.builder, 'args'):
                        orig_command = ' > \033[90m' + \
                            ' '.join(step.builder.args) + '\033[0m\n'
                        print(orig_command)
                    step.builder.stderr.seek(0)
                    stderr = step.builder.stderr.read().decode('utf-8')
                    for line in stderr.split('\n'):
                        print('  ' + step.stderr_prettifier(line))
                    self.interrupt()
                    return False
                step.builder = None
                del self.pid_to_step[pid]
                on_step_finished(step)
            else:
                next = ready_steps.pop()
                try:
                    builder = next.build_if_needed()
                    if builder:
                        next.builder = builder
                        self.pid_to_step[builder.pid] = next
                    else:
                        on_step_finished(next)
                except subprocess.CalledProcessError:
                    print(f'Recipe for {next.name} finished with an error.')
                    self.interrupt()
                    return False
                except FileNotFoundError as err:
                    print(f'Recipe for {next.name} couldn\'t find file {err}')
                    self.interrupt()
                    return False
        print(
            f'Build took {time.time() - start_time:.3f} seconds ({len(self.steps)} steps)')
        return True

    def interrupt(self):
        start_time = time.time()
        deadline = start_time + 3
        active = [step.builder for step in self.steps if step.builder]
        if platform != 'win32':
            for task in active:
                task.send_signal(signal.SIGINT)
        for task in active:
            time_left = deadline - time.time()
            if time_left > 0:
                task.wait(time_left)
        for task in active:
            task.kill()
