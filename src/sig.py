import make
import build


def hook_final(srcs, objs, bins: list[build.Binary], recipe: make.Recipe):
    for bin in bins:
        # Only sign files which included sig.hh (and thus have a sig.x script)
        if '-Wl,--script=src/sig.x' not in bin.link_args:
            continue
        bin_signed_path = bin.path.with_stem('signed_' + bin.path.stem)

        def sign(bin=bin, bin_signed_path=bin_signed_path):
            return make.Popen(['build/elf_signer', '~/.ssh/id_ed25519', bin.path, bin_signed_path])

        recipe.add_step(sign, [bin_signed_path], [
                        bin.path, 'build/elf_signer'], desc=f'Signing {bin_signed_path}', shortcut=f'sign {bin.path.stem}')
