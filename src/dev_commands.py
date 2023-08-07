'''Commands used for development.'''

import make


def run(args: str):
    return make.Popen(args.split(),
                      env={
                          'PORTABLE': '1',
                          'LAN': 'enxe8802ee74415'
                      })


def debug():
    return run('build/debug_gatekeeper')


def gdb():
    return run('gdb build/debug_gatekeeper -g -ex run')


def valgrind():
    return run(
        'valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt build/debug_gatekeeper'
    )


def massif():
    return run(
        'valgrind --tool=massif --stacks=yes --massif-out-file=massif-out.txt build/debug_gatekeeper'
    )


def net_reset():
    import subprocess
    subprocess.run('sudo nft delete table gatekeeper', shell=True)
    subprocess.run('sudo ip addr flush dev enxe8802ee74415', shell=True)


def test_e2e():
    return make.Popen(['sudo', './test_e2e.sh'])


def hook_final(srcs, objs, bins, recipe: make.Recipe):
    deps = ['build/debug_gatekeeper']
    recipe.add_step(debug, [], deps)
    recipe.add_step(gdb, [], deps)
    recipe.add_step(valgrind, [], deps)
    recipe.add_step(massif, [], deps)
    recipe.add_step(net_reset, [], deps)
    recipe.add_step(test_e2e, [], deps)
