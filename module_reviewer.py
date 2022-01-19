#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2020 Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License

from __future__ import absolute_import, division, print_function

import sys

from argparse import ArgumentParser
from subprocess import Popen, PIPE

from yaml import safe_load, dump


def get_cli_args():
    """Gets, parses, and returns CLI arguments"""
    parser = ArgumentParser(description='Check modules formatting')

    parser.add_argument('filepath', help='path to a file to check')

    parser.add_argument('-n', '--fqcn',
                        dest='fqcn',
                        metavar='FQCN',
                        default=False,
                        required=False,
                        help='FQCN to check examples')

    parser.add_argument("-c", "--comments",
                        dest="check_comments",
                        action="store_true",
                        required=False,
                        help="check comments")

    parser.add_argument("-l", "--length",
                        dest="check_length",
                        action="store_true",
                        required=False,
                        help="check description length")

    parser.add_argument("-s", "--spelling",
                        dest="check_spelling",
                        action="store_true",
                        required=False,
                        help="check spelling")

    return parser.parse_args()


def get_sections_to_check(module_path, check_comments):
    """Reads a module file and extracts section to check"""
    documentation = []
    examples = []
    returns = []
    messages = []

    is_in_doc_section = False
    is_in_examples_section = False
    is_in_return_section = False
    is_in_message = False
    is_in_method = False
    end_of_method_def = False

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

            # Extract comments if needed
            if check_comments:
                if '# ' in line and not (is_in_doc_section or
                                         is_in_examples_section or
                                         is_in_return_section or
                                         is_in_message):
                    if "Copyright" not in line:
                        messages.append(line.split('#')[1].strip())

            # Extract class / function comments
            if ("def " in line or "class " in line):
                if not (is_in_doc_section or
                        is_in_examples_section or
                        is_in_return_section or
                        is_in_message):
                    is_in_method = True

            if is_in_method and line[-2:] == ':\n':
                end_of_method_def = True

            if is_in_method and end_of_method_def:
                if ' """' in line or " '''" in line:
                    messages.append(line)

                if '"""\n' in line or "'''\n" in line:
                    is_in_method = False
                    end_of_method_def = False
                    continue
            # End of extracting function comments

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
        documentation = safe_load(documentation)
    except AttributeError:
        pass

    try:
        examples = safe_load(examples)
    except AttributeError:
        pass

    try:
        returns = safe_load(returns)
    except AttributeError:
        pass
    except Exception as e:
        print('Cannot parse RETURN section: %s' % e)
        returns = ['empty']

    messages = extract_messages(messages)

    return documentation, examples, returns, messages


def extract_messages(messages):
    """Extracts and returns messages"""
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
    """Extracts a message from module.warn() method invocation"""
    elem = elem.split('(')[1:]
    elem = ' '.join(elem).rstrip(')')

    elem = extract_msg(elem)

    return elem


def extract_module_fail_msg(elem):
    """Extracts a message from module.fail_json() method invocation"""
    elem = elem.split('=')[1:]
    elem = ' '.join(elem).rstrip(')')

    elem = extract_msg(elem)

    return elem


def extract_msg(elem):
    """Extracts a message"""
    if ' % ' in elem:
        elem = elem.split(' % ')[:-1]
        elem = ''.join(elem)

    elem = elem.rstrip(')').strip('"').strip("'")
    return elem


def check_forbidden_words(line, report, prefix=None):
    """Searches for forbidden expressions"""
    # 'forbidden word': 'alternative'
    FORBIDDEN_WORDS = {
        'via ': 'by/through',
        'e.g.': 'for example',
        'etc.': 'and so on',
        'etc,': 'and so on',
        'etc)': 'and so on',
        'etc\n': 'and so on',
        'i.e.': 'in other words',
        ' vs ': 'rather than/against',
        'vs ': 'rather than/against',
        ' vs)': 'rather than/against',
        'versus': 'rather than/against',
        "it's": 'it is',
        "ain't": 'corresponding expression',
        "you're": 'you are',
        "they're": 'they are',
        "doesn't": 'does not',
        "don't": 'do not',
        "won't": 'will not',
        "wasn't": 'was not',
        "weren't": 'were not',
        "mustn't": 'must not',
        "should't": 'should not',
        "can't": 'cannot"',
        "couldn't": 'could not',
        "mightn't": 'might not',
        "wouldn't": 'would not',
    }

    for key in FORBIDDEN_WORDS:
        if key in line.lower():
            if prefix:
                report.append("%s: abbreviations/latin phrases found '%s', "
                              "use '%s' instead" % (prefix, key, FORBIDDEN_WORDS[key]))
            else:
                report.append("abbreviations/latin phrases found '%s', "
                              "use '%s' instead" % (key, FORBIDDEN_WORDS[key]))


def check_doc_section(doc, report, check_length, spelling):
    """Checks the documentation section"""
    # If there is no the documentation block, exit
    if not doc:
        print('"DOCUMENTATION" section is not provided, '
              'nothing to parse, exit')
        sys.exit(1)

    check_descr([doc['short_description'], ], report,
                'short_description', check_length)

    if 'description' in doc:
        if isinstance(doc['description'], str):
            doc['description'] = [doc['description'], ]

        check_descr(doc['description'], report,
                    'description', check_length)
    else:
        report.append('no description section')

    if 'options' in doc:
        check_doc_options(doc['options'], report, check_length)

    if doc.get('notes'):
        if isinstance(doc['notes'], str):
            doc['notes'] = [doc['notes'], ]

        check_descr(doc['notes'], report, 'notes', check_length)

        check_mode_mentioned(doc['notes'], report, 'notes')

    else:
        report.append('no "notes" section, it should, at least, contain '
                      'info about check_mode support')

    if spelling:
        check_spelling(dump(doc), 'Possible typos in DOCUMENTATION:')


def check_mode_mentioned(str_list, report, d_type):
    """Checks if the check mode support is mentioned"""
    mentioned = False
    for line in str_list:
        if 'check_mode' in line.lower() or 'check mode' in line.lower():
            mentioned = True

    if not mentioned:
        report.append('%s: check_mode support is not mentioned' % d_type)


def check_doc_options(options, report, check_length):
    """Checks module options"""
    for opt_name, content in options.items():
        if 'description' in content:
            check_descr(content['description'], report,
                        'opt %s' % opt_name, check_length)
        else:
            # In case of plugins
            report.append('opt %s: no description provided' % opt_name)

        # We do not need to declare "required: false" explicitly
        # if 'required' in content and not content['required']:
        #     report.append('opt %s: explicit "require: false" '
        #                   'declaration' % opt_name)


def check_descr(description, report, d_type, check_length):
    """Checks option / return value descriptions"""
    LINE_MAX_LEN = 200

    if isinstance(description, str):
        description = [description, ]

    # Check if every line of description starts with a capital letter
    # and ends with a dot
    for n, line in enumerate(description):
        # Are there latin words and phrases?
        check_forbidden_words(line, report, prefix=d_type)

        # Starts with uppercase?
        if not line[0].isupper() and not line[0].isdigit():
            report.append("%s: line %s does not start "
                          "with a capital letter" % (d_type, n + 1))

        # Ends with a proper symbol?
        if line[-1] != '.' and d_type != 'short_description':
            if len(line) >= 2 and line[-1] not in ('.', '!'):
                report.append("%s: line %s does not "
                              "end with a dot" % (d_type, n + 1))

        if line[-1] == '.' and d_type == 'short_description':
            report.append("%s: line %s "
                          "ends with a dot" % (d_type, n + 1))

        # Uses a marker with http?
        if needs_marker(line, 'http://', 'U') or needs_marker(line, 'https://', 'U'):
            report.append("%s: has URLs "
                          "used without U() marker" % d_type)

        # Check length
        if check_length:
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
        if string[marker_check_pos] != marker and 'L(' not in string:
            return True

    return False


def check_examples_section(examples, report, fqcn=None, spelling=None):
    """Checks the examples section"""
    has_provided_fqcn = False

    if not examples:
        report.append('EXAMPLES section is empty or fully commented')
        return

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

        # FQCN check
        has_fqcn = False

        for key in ex:
            if '.' in key or key == 'assert':
                has_fqcn = True

            if fqcn and fqcn in key:
                has_provided_fqcn = True

        if has_fqcn:
            has_fqcn = False
        else:
            report.append('examples: #%s no FQCN' % (n + 1))

    # When we have not found a provided FQCN
    # in the EXAMPLES section
    if fqcn and not has_provided_fqcn:
        report.append("examples: there is no example "
                      "containing provided FQCN %s" % fqcn)

    if spelling:
        check_spelling(dump(examples), 'Possible typos in EXAMPLES:')


def check_return_section(returns, report, check_length, spelling):
    """Checks the return section"""
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
                    'return %s' % key, check_length)

        if not returns[key].get('sample'):
            report.append('return %s: no sample' % key)

    if spelling:
        check_spelling(dump(returns), 'Possible typos in RETURN:')


def check_spelling(data, header_to_print=None):
    """Checks spelling via Yandex.Speller API"""
    try:
        p = Popen(['./yasp'], stdin=PIPE, stdout=PIPE, encoding='UTF-8')
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
    # Parse CLI arguments
    args = get_cli_args()

    # Extract sections
    doc, examples, returns, messages = get_sections_to_check(args.filepath,
                                                             args.check_comments)

    # Create a report object
    report = []

    # Check the documentation section
    check_doc_section(doc, report, args.check_length, args.check_spelling)

    # Check the examples section
    check_examples_section(examples, report, args.fqcn, args.check_spelling)

    # Check the return section
    check_return_section(returns, report, args.check_length, args.check_spelling)

    # Check comments and messages
    messages = ' '.join(messages)

    if args.check_spelling:
        check_spelling(messages, 'Possible typos in the file:')

    check_forbidden_words(messages, report)

    # Print the report
    for line in report:
        print(line)


if __name__ == '__main__':
    main()
