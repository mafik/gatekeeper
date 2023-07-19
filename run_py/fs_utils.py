'''Utilities for operating on filesystem.'''

from pathlib import Path

# The `run_py` directory is symlinked from different projects.
# Calling `resolve()` on `__file__` would leave the project directory so first step out with `parents[1]` and then resolve.
project_root = Path(__file__).absolute().parents[1].resolve()
project_name = Path(project_root).name.lower()

build_dir = project_root / 'build'
src_dir = project_root / 'src'
