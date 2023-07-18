import cc


def CMakeArgs(optimized, debug):
    if optimized and debug:
        CMAKE_BUILD_TYPE = 'RelWithDebInfo'
    elif optimized:
        CMAKE_BUILD_TYPE = 'Release'
    elif debug:
        CMAKE_BUILD_TYPE = 'Debug'
    else:
        CMAKE_BUILD_TYPE = 'MinSizeRel'

    cmake_args = ['cmake', '-G', 'Ninja', f'-D{CMAKE_BUILD_TYPE=}',
                  f'-DCMAKE_C_COMPILER={cc.CC}', f'-DCMAKE_CXX_COMPILER={cc.CXX}']

    # CMake needs this policy to be enabled to respect `CMAKE_MSVC_RUNTIME_LIBRARY`
    # https://cmake.org/cmake/help/latest/policy/CMP0091.html
    # When vk-bootstrap sets minimum CMake version >= 3.15, the policy define can be removed.
    CMAKE_MSVC_RUNTIME_LIBRARY = 'MultiThreadedDebug' if debug else 'MultiThreaded'
    cmake_args += ['-DCMAKE_POLICY_DEFAULT_CMP0091=NEW',
                   f'-D{CMAKE_MSVC_RUNTIME_LIBRARY=}']

    return cmake_args
