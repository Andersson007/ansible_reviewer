#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function

from subprocess import Popen, PIPE

import sys

from yaml import load, dump


LINE_MAX_LEN = 200


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
    messages = []

    is_in_doc_section = False
    is_in_examples_section = False
    is_in_return_section = False
    is_in_message = False

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

            # Extract comments
            if '# ' in line and not (is_in_doc_section or
                                     is_in_examples_section or
                                     is_in_return_section or
                                     is_in_message):
                if "Copyright" not in line:
                    messages.append(line.split('#')[1].strip())

            # Detect end of a message
            if is_in_message and line[-2:] == ')\n':
                messages.append(line)
                is_in_message = False
                continue

            # Start to extract the documentation section
            if 'DOCUMENTATION =' in line:
                is_in_doc_section = True
                continue

            # Start to extract the examples section
            elif 'EXAMPLES =' in line:
                is_in_examples_section = True
                continue

            # Start to extract the return section
            elif 'RETURN =' in line:
                if '#' in line:
                    returns.append('empty')
                    continue

                is_in_return_section = True
                continue

            # Start to extract messages
            elif 'module.fail_json' in line or 'module.warn' in line:
                is_in_message = True

            # Put the line in an appropriate list
            if is_in_doc_section:
                documentation.append(line)

            elif is_in_examples_section:
                examples.append(line)

            elif is_in_return_section:
                returns.append(line)

            elif is_in_message:
                messages.append(line)

    if documentation:
        documentation = ''.join(documentation)

    if examples:
        examples = ''.join(examples)

    if returns and not returns[0] == 'empty':
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

    messages = handle_messages(messages)

    return documentation, examples, returns, messages


def handle_messages(messages):

    tmp_list = []

    for elem in messages:
        if elem == '\n':
            continue

        elem = elem.rstrip('\n').lstrip(' ')

        if 'module.warn' in elem:
            elem = extract_module_warn_msg(elem)

        elif 'module.fail_json' in elem:
            elem = extract_module_fail_msg(elem)

        else:
            elem = extract_msg(elem)

        tmp_list.append(elem)

    return tmp_list


def extract_module_warn_msg(elem):
    elem = elem.split('(')[1:]
    elem = ' '.join(elem).rstrip(')')

    elem = extract_msg(elem)

    return elem


def extract_module_fail_msg(elem):
    elem = elem.split('=')[1:]
    elem = ' '.join(elem).rstrip(')')

    elem = extract_msg(elem)

    return elem


def extract_msg(elem):
    if ' % ' in elem:
        elem = elem.split(' % ')[:-1]
        elem = ''.join(elem)

    elem = elem.rstrip(')').strip('"').strip("'")
    return elem


def check_comments_and_msgs(msg_list):
    check_spelling(' '.join(msg_list), 'Possible typos in comments and messages')


def check_doc_section(doc, report):
    """Check the documentation section"""

    # If there is no the documentation block, exit
    if not doc:
        raise AttributeError('"DOCUMENTATION" section is not provided, '
                             'nothing to parse, exit')

    check_descr([doc['short_description'], ], report, 'short_description')

    if 'description' in doc:
        if isinstance(doc['description'], str):
            doc['description'] = [doc['description'], ]

        check_descr(doc['description'], report, 'description')
    else:
        report.append('no description section')

    check_doc_options(doc['options'], report)

    if doc.get('notes'):
        if isinstance(doc['notes'], str):
            doc['notes'] = [doc['notes'], ]

        check_descr(doc['notes'], report, 'notes')

        check_mode_mentioned(doc['notes'], report, 'notes')

    else:
        report.append('no "notes" section, it should, at least, contain '
                      'info about check_mode support')

    check_spelling(dump(doc), 'Possible typos in DOCUMENTATION:')


def check_mode_mentioned(str_list, report, d_type):
    mentioned = False
    for line in str_list:
        if 'check_mode' in line.lower() or 'check mode' in line.lower():
            mentioned = True

    if not mentioned:
        report.append('%s: check_mode support is not mentioned' % d_type)


def check_doc_options(options, report):
    for opt_name, content in options.items():
        if 'description' in content:
            check_descr(content['description'], report, 'opt %s' % opt_name)
        else:
            # In case of plugins
            report.append('opt %s: no description provided' % opt_name)

        # We do not need to declare "required: false" explicitly
        if 'required' in content and not content['required']:
            report.append('opt %s: explicit "require: false" '
                          'declaration' % opt_name)


def check_descr(description, report, d_type):
    if isinstance(description, str):
        description = [description, ]

    # Check if every line of description starts with a capital letter
    # and ends with a dot
    for n, line in enumerate(description):
        # Starts with uppercase?
        if not line[0].isupper() and not line[0].isdigit():
            report.append("%s: line %s does not start "
                          "with a capital letter" % (d_type, n + 1))

        # Ends with a proper symbol?
        if line[-1] != '.' and d_type != 'short_description':
            if len(line) >= 2 and line[1] != ')':
                report.append("%s: line %s does not "
                              "end with a dot" % (d_type, n + 1))

        if line[-1] == '.' and d_type == 'short_description':
            report.append("%s: line %s "
                          "ends with a dot" % (d_type, n + 1))

        # Uses a marker with http?
        if needs_marker(line, 'http', 'U'):
            report.append("%s: has URLs "
                          "used without U() marker" % d_type)

        # Check length
        line_len = len(line)
        if line_len > LINE_MAX_LEN:
            report.append("%s: line %s contains %s characters which seems "
                          "to be too long" % (d_type, n, line_len))


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


def check_examples_section(examples, report, fqcn=None):
    for n, ex in enumerate(examples):
        if 'name' not in ex:
            report.append('examples: #%s without using "name"' % (n + 1))

        else:
            if not ex['name'][0].isupper():
                report.append('examples: "- name" of #%s does not start '
                              'with a capital letter' % (n + 1))

            if ex['name'][-1] == '.':
                report.append('examples: "- name" of #%s '
                              'ends with a dot' % (n + 1))

        if fqcn and fqcn not in ex:
            report.append("examples: #%s there is "
                          "no FQCN %s" % (n + 1, fqcn))

        else:
            has_fqcn = False
            for key in ex:
                if '.' in key:
                    has_fqcn = True

            if has_fqcn:
                has_fqcn = False
            else:
                report.append('examples: #%s no FQCN' % (n + 1))

    check_spelling(dump(examples), 'Possible typos in EXAMPLES:')


def check_return_section(returns, report):
    if not returns:
        report.append('return: no RETURN section, there must be, '
                      'at least, RETURN = r"""#"""')
        return

    elif isinstance(returns, list) and returns[0] == 'empty':
        return

    for key in returns:
        if isinstance(returns[key]['description'], str):
            returns[key]['description'] = [returns[key]['description'], ]

        check_descr(returns[key]['description'], report,
                    'return %s' % key)

        if not returns[key].get('sample'):
            report.append('return %s: no sample' % key)

    check_spelling(dump(returns), 'Possible typos in RETURN:')


def check_spelling(data, header_to_print=None):
    try:
        p = Popen(['./yasp'], stdin=PIPE, stdout=PIPE)
        p.stdin.write(data)

        output = p.communicate()[0]

        if output:
            if header_to_print:
                print(header_to_print)

            print(output, end='')
            print('-' * 20)
        p.stdin.close()
    except Exception as e:
        print('Cannot communicate with '
              'Yandes Speller API, skipped: %s' % e)


def main():

    # Check CLI arguments
    check_cli_args(sys.argv)

    # Extract sections
    doc, examples, returns, messages = get_sections_to_check(sys.argv[1])
    print(messages)

    # Create a report object
    report = []

    # Check the documentation section
    check_doc_section(doc, report)

    # Check the examples section
    check_examples_section(examples, report)

    # Check the return section
    check_return_section(returns, report)

    # Check comments and messages
    check_comments_and_msgs(messages)

    # Print the report
    for line in report:
        print(line)


if __name__ == '__main__':
    main()
