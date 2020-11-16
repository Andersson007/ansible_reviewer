#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function


import sys

from yaml import load


def check_cli_args(arg_list):
    """Checks CLI arguments"""
    # Maybe later it'll be argparser
    # but this primitive check is enough for a while
    if len(sys.argv) < 2:
        raise Exception('At least one argument (file name) is required. Exit')


def get_sections_to_check(module_path):
    """Read a module file and extracts section to check"""

    DOCUMENTATION = []
    EXAMPLES = []
    RETURN = []

    is_in_doc_section = False
    is_in_examples_section = False
    is_in_return_section = False

    with open(module_path, 'r') as f:
        for line in f:
            # End of thesection has been reached
            if line in ('"""\n', "'''\n"):
                if is_in_doc_section:
                    is_in_doc_section = False

                elif is_in_examples_section:
                    is_in_examples_section = False

                elif is_in_return_section:
                    is_in_return_section = False

                continue

            # Start to extract the DOCUMENTATION section
            if 'DOCUMENTATION' in line:
                is_in_doc_section = True
                continue

            # Start to extract the EXAMPLES section
            elif 'EXAMPLES' in line:
                is_in_examples_section = True
                continue

            # Start to extract the RETURN section
            elif 'RETURN' in line:
                is_in_return_section = True
                continue

            # Put the line in an appropriate list
            if is_in_doc_section:
                DOCUMENTATION.append(line)

            elif is_in_examples_section:
                EXAMPLES.append(line)

            elif is_in_return_section:
                RETURN.append(line)

    if DOCUMENTATION:
        DOCUMENTATION = ''.join(DOCUMENTATION)

    if EXAMPLES:
        EXAMPLES = ''.join(EXAMPLES)

    if RETURN:
        RETURN = ''.join(RETURN)

    try:
        DOCUMENTATION = load(DOCUMENTATION)
    except AttributeError:
        pass

    try:
        EXAMPLES = load(EXAMPLES)
    except AttributeError:
        pass

    try:
        RETURN = load(RETURN)
    except AttributeError:
        pass

    return DOCUMENTATION, EXAMPLES, RETURN


def main():

    # Check CLI arguments
    check_cli_args(sys.argv)

    # Extract sections
    DOCUMENTATION, EXAMPLES, RETURN = get_sections_to_check(sys.argv[1])

    # If there is no DOCUMENTATION block, exit
    if not DOCUMENTATION:
        raise AttributeError('"DOCUMENTATION" section is not provided, '
                             'nothing to parse, exit')


if __name__ == '__main__':
    main()
