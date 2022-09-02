#!/usr/bin/env python
# WTFPL - Do What the Fuck You Want to Public License
from __future__ import print_function
import argparse
import pathlib
import pefile
import os
import sys


def get_dependency(filename):
    deps = []
    pe = pefile.PE(filename)
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        deps.append(imp.dll.decode())
    return deps


def dep_tree(root, prefixes=None, thread=None, verbose=False):
    if not prefixes or thread:
        arch = get_arch(root)
        if verbose:
            print('Arch =', arch)
    if not prefixes:
        prefixes = ['/usr/'+arch+'-w64-mingw32/bin']
        if verbose:
            print('Using default prefix', prefixes[0])
    if thread:
        prefixes.append('/usr/lib/gcc/'+arch+'-w64-mingw32/10-'+thread)
        if verbose:
            print('Adding prefix based on thread', prefixes[-1])

    dep_dlls = dict()

    def dep_tree_impl(root):
        for dll in get_dependency(root):
            if dll in dep_dlls:
                continue
            for prefix in prefixes:
                full_path = os.path.join(prefix, dll)
                if not os.path.exists(full_path):
                    continue
                dep_dlls[dll] = full_path
                dep_tree_impl(full_path)
            if dll not in dep_dlls:
                dep_dlls[dll] = 'not found'

    dep_tree_impl(root)
    return (dep_dlls)


def get_arch(filename):
    type2arch= {pefile.OPTIONAL_HEADER_MAGIC_PE: 'i686',
                pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: 'x86_64'}
    pe = pefile.PE(filename)
    try:
        return type2arch[pe.PE_TYPE]
    except KeyError:
        sys.stderr.write('Error: unknown architecture')
        sys.exit(1)

def main(argv):
    parser = argparse.ArgumentParser(prog=os.path.basename(argv[0]),
            description='Recursively resolves dependencies of PE executables')
    parser.add_argument('-D', '--prefix', metavar='path', type=pathlib.Path,
            action='append', dest='prefixes',
            help='Add prefix path to search for DLLs, can be given'
               + ' multiple times')
    parser.add_argument('-t', '--thread', choices=['win32', 'posix'],
            help='Thread model used by GCC. Specifying this adds the'
               + ' appropriate prefix path to the list')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='Display additional information')
    parser.add_argument('executable', type=argparse.FileType('r'),
            help='The PE executable file to check or dependencies')
    args = parser.parse_args(argv[1:])
    args.executable.close()
    for dll, full_path in dep_tree(args.executable.name, args.prefixes,
            args.thread, args.verbose).items():
        print(' ' * 7, dll, '=>', full_path)

if __name__ == '__main__':
    main(sys.argv)
