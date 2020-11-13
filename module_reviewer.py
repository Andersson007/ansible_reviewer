#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function


import sys


def check_cli_args(arg_list):
    # Maybe later it'll be argparser
    # but this primitive check is enough for a while.
    if len(sys.argv) < 2:
        raise Exception('At least one argument (file name) is required. Exit')


def main():

    # Check CLI arguments
    check_cli_args(sys.argv)

    # Load the passed module,
    # it must be in the same directory.
    # Modules names cannot contain extensions,
    # so we must cut it off.
    # The module file must be in the current directory.
    # It can be passed with or without an extension.
    module = sys.argv[1].split('.')[0] if '.' in sys.argv[1] else sys.argv[1]
    module = __import__(module) 

    print(module.DOCUMENTATION)


if __name__ == '__main__':
    main()
