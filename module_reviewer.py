#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function


import sys

from yaml import load


LINE_MAX_LEN = 79


def check_cli_args(arg_list):
    """Checks CLI arguments"""
    # Maybe later it'll be argparser
    # but this primitive check is enough for a while
    if len(sys.argv) < 2:
        raise Exception('At least one argument (file name) is required. Exit')


def get_sections_to_check(module_path):
    """Read a module file and extracts section to check"""

    documentation = []
    examples = []
    returns = []

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

            # Start to extract the documentation section
            if 'DOCUMENTATION' in line:
                is_in_doc_section = True
                continue

            # Start to extract the examples section
            elif 'EXAMPLES' in line:
                is_in_examples_section = True
                continue

            # Start to extract the return section
            elif 'RETURN' in line:
                is_in_return_section = True
                continue

            # Put the line in an appropriate list
            if is_in_doc_section:
                documentation.append(line)

            elif is_in_examples_section:
                examples.append(line)

            elif is_in_return_section:
                returns.append(line)

    if documentation:
        documentation = ''.join(documentation)

    if examples:
        examples = ''.join(examples)

    if returns:
        returns = ''.join(returns)

    try:
        documentation = load(documentation)
    except AttributeError:
        pass

    try:
        examples = load(examples)
    except AttributeError:
        pass

    try:
        returns = load(returns)
    except AttributeError:
        pass

    return documentation, examples, returns


def check_doc_section(doc, report):
    """Check the documentation section"""

    # If there is no the documentation block, exit
    if not doc:
        raise AttributeError('"DOCUMENTATION" section is not provided, '
                             'nothing to parse, exit')

    # Check if short_description starts with a capital letter
    # and does not end with a dot
    if not doc['short_description'][0].isupper():
        report.append("module's short_description: does not start "
                      "with a capital letter")

    if doc['short_description'][-1] == '.':
        report.append("module's short_description: ends with a dot")

    # Check if every line of description starts with a capital letter
    # and ends with a dot
    for n, line in enumerate(doc['description']):
        # Starts with uppercase?
        if not line[0].isupper():
            report.append("module's description: line %s does not start "
                          "with a capital letter" % (n + 1))

        # Ends with a dot?
        if line[-1] != '.':
            report.append("module's description: line %s does not "
                          "end with a dot" % (n + 1))

        # Uses a marker with http?
        if needs_marker(line, 'http', 'U'):
            report.append("module's description: has URLs "
                          "used without U() marker")

        # Check length
        line_len = len(line)
        if line_len > LINE_MAX_LEN:
            report.append("module's description: line %s is %s characters "
                          "long which is longer than %s. Would not be better "
                          "to split them?" % (n, line_len, LINE_MAX_LEN))


def needs_marker(string, pattern, marker):
    """Check if a substring is following a certain marker.

    Args:
      string (str) - string to search in
      pattern (str) - pattern to search for
      marker (str) - marker to be followed by pattern, can be U, C, M, etc.
    """

    pattern_start_pos = string.find(pattern)

    if pattern_start_pos != -1:
        if pattern_start_pos < 2:
            return True

        marker_check_pos = pattern_start_pos - 2
        if string[marker_check_pos] != marker:
            return True

    return False


def main():

    # Check CLI arguments
    check_cli_args(sys.argv)

    # Extract sections
    documentation, examples, returns = get_sections_to_check(sys.argv[1])

    # Create a report object
    report = []

    # Check the documentation section
    check_doc_section(documentation, report)

    # TODO: Debug
    for line in report:
        print(line)


if __name__ == '__main__':
    main()
