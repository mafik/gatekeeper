import make
import src
import build


def hook_srcs(srcs: dict[str, src.File], recipe):
    for file in srcs.values():
        if not file.main:
            continue
        file.link_args['release'].append('-Wl,--script=src/sig.x')
        file.direct_includes.append('src/sig.hh')


def hook_final(srcs, objs, bins: list[build.Binary], recipe: make.Recipe):
    bin_paths = set(str(bin.path)
                    for bin in bins if bin.build_type == 'release')
    for step in recipe.steps:
        bin_outputs = set(step.outputs) & bin_paths
        if bin_outputs:
            step.desc += ' (signed)'
            for bin in bin_outputs:
                def build_and_sign(orig_build=step.build):
                    orig_builder = orig_build()
                    # TODO: actually sign bin
                    return orig_builder
                step.build = build_and_sign
