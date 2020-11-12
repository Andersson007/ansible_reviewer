#!/usr/bin/python3
# Copyright: (c) 2020, Andrew Klychkov (@Andersson007) <aaklychkov@mail.ru>
# MIT License
#
# Requirements:
# 1. pip3 install PyGithub
# 2. GitHub access token
#
# Example:
# ./issue_copier.py -t your_github_token_here \
# -s ansible/ansible -d Andersson007/test_repo -i 51399

from argparse import ArgumentParser

from github import Github

__VERSION__ = '0.1'


def get_cli_args():
    """Get command-line arguments."""
    parser = ArgumentParser(description='Copy issue from a repo to another one.')

    # Access token
    parser.add_argument('-t', '--token', dest='token', required=True,
                        help='GitHub access token', metavar='TOKEN')

    # Source repo
    parser.add_argument('-s', '--src-repo', dest='src_repo', required=True,
                        help='Source GitHub repository (e.g. ansible/ansible)',
                        metavar='SRC_REPO')

    # Destination repo
    parser.add_argument('-d', '--dst-repo', dest='dst_repo', required=True,
                        help='Destination GitHub repository (e.g. MyLogin/test_repo)',
                        metavar='DST_REPO')

    # Issue number
    parser.add_argument('-i', '--issue-num', dest='issue_num', required=True,
                        help='Number of issue that needs to be copied',
                        metavar='ISSUE_NUM')

    # Assignee
    parser.add_argument('-a', '--assignee', dest='assignee',
                        action='store_true', help='copy assignee')

    # Labels
    parser.add_argument('-L', '--labels', dest='labels',
                        action='store_true', help='copy labels')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('-v', '--version', action='version',
                       version=__VERSION__, help='show version and exit')

    return parser.parse_args()


def main():
    # Defaults
    assignee = ''
    labels = []

    # Get command-line arguments:
    cli_args = get_cli_args()
    src_issue_num = int(cli_args.issue_num)

    # Create github object and set access token:
    g = Github(cli_args.token)

    # Set repos:
    src_repo = g.get_repo(cli_args.src_repo)
    dst_repo = g.get_repo(cli_args.dst_repo)

    # Set source issue:
    src_issue = src_repo.get_issue(number=src_issue_num)

    # Get issue's content:
    author = src_issue.user.login
    body = src_issue.body

    if cli_args.assignee:
        assignee = src_issue.assignee
        if not assignee:
            assignee = ''

    if cli_args.labels:
        labels = src_issue.labels
        if not labels:
            labels = []

    info_about_prev_issue = ('_Copied from https://github.com/%s/issues/%s_\n'
                             '_Initially reported by @%s_\n\n' % (cli_args.src_repo,
                                                                  src_issue_num,
                                                                  author))

    title = src_issue.title
    body = info_about_prev_issue + body

    # Create a new issue in the destination repo:
    dst_repo.create_issue(title=title,
                          body=body,
                          assignee=assignee,
                          labels=labels)


if __name__ == '__main__':
    main()
