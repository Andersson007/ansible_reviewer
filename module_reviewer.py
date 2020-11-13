#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function


import sys


def check_cli_args(arg_list):
    """Checks CLI arguments"""
    # Maybe later it'll be argparser
    # but this primitive check is enough for a while
    if len(sys.argv) < 2:
        raise Exception('At least one argument (file name) is required. Exit')


def get_sections_to_check(module_name):
    """Loads a module by name and extracts section to check"""
    # Load the passed module,
    # it must be in the same directory.
    # Modules names cannot contain extensions,
    # so we must cut it off.
    # The module file must be in the current directory.
    # It can be passed with or without an extension
    module = module_name.split('.')[0] if '.' in module_name else module_name
    module = __import__(module)

    DOCUMENTATION = None
    EXAMPLES = None
    RETURN = None

    try:
        DOCUMENTATION = module.DOCUMENTATION
    except AttributeError:
        pass

    try:
        EXAMPLES = module.EXAMPLES
    except AttributeError:
        pass

    try:
        RETURN = module.RETURN
    except AttributeError:
        pass

    return DOCUMENTATION, EXAMPLES, RETURN


def main():

    # Check CLI arguments
    check_cli_args(sys.argv)

    # Extract sections
    DOCUMENTATION, EXAMPLES, RETURN = get_sections_to_check(sys.argv[1])

    # If there is no DOCUMENTATION block, exit 
    if DOCUMENTATION is None:
        raise AttributeError('"DOCUMENTATION" section is not provided, '
                             'nothing to parse, exit')


if __name__ == '__main__':
    main()
