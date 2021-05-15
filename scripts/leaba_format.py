#!/usr/bin/python
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

# Apply copyright notice to source files.
#
# Supported types:
#    C/C++ (.c, .cpp, .h)
#    SWIG (.i)
#    NPL (.npl)
#    Python (.py)
#    Perl (.pl)
#    Makefiles (Makefile*)

import argparse
import os
import re
import shutil
import tempfile
import datetime
import subprocess
import shlex
import pathlib

clang_filetype_regex = '.*(\.h|\.c|\.cpp|\.tcc)$'
autopep_filetype_regex = '.*\.py$'
cstyle_comment_regex = '.*(\.i|\.npl)$|%s' % clang_filetype_regex
hashtag_comment_regex = '.*\.pl$|[Mm]akefile.*|%s' % autopep_filetype_regex
reformat_include_regex = '%s|%s' % (cstyle_comment_regex, hashtag_comment_regex)


reformat_exclude_regex = '^(out|output|test_output|npls)|/(out|output|test_output|npls)|\~'

notice = None


FORMAT_SUCCESSFUL = 0
FORMAT_ERROR_CONTINUE = 1
FORMAT_ERROR_ABORT = 2


def collect_files(user_files, user_dirs):
    collected_files = []

    for path in user_files:
        if re.search(reformat_exclude_regex, path):
            continue
        if re.search(reformat_include_regex, path):
            collected_files.append(path)

    for root in user_dirs:
        for directory, sub_directories, files in os.walk(root):
            for file in files:
                path = os.path.join(directory, file)
                if re.search(reformat_exclude_regex, path):
                    continue

                if re.search(reformat_include_regex, path):
                    collected_files.append(path)

    return collected_files


def read_notice(file):
    global notice
    notice = []

    notice = open(args.notice).read().splitlines()


def run_command(command):
    command_split = shlex.split(command)
    command_proc = subprocess.Popen(command_split, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (std_out, std_err) = command_proc.communicate()
    return (command_proc.returncode, std_out, std_err)


def find_start_year(orig):
    found = False

    # Try to read the start year from the legal header if exists
    with open(orig, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    begin_legal_line = None
    for i, l in enumerate(lines[:10]):
        if 'BEGIN' + '_' + 'LEGAL' in l:
            begin_legal_line = i
            break

    if begin_legal_line is not None:
        m = re.match(r'.*\(c\) ([0-9]{4})', lines[begin_legal_line + 2])
        if m is not None:
            start_year = int(m.group(1))
            found = True

    # If failed reading from legal header read from git log
    if not found:
        command = 'git log --follow --find-renames=90%% --diff-filter=A --pretty=format:"%%ad" -- %s' % orig
        (returncode, std_out, std_err) = run_command(command)
        if returncode == 0:
            git_log = std_out
            m = re.search(b'.*:.*:[^ ]* (\d{4}) .*', git_log)
            if m:
                start_year = int(m.group(1))
                found = True

    if not found:
        p = pathlib.Path(orig)
        print('ERROR: %s does not have a first appearance date in its header or log.' % p.absolute())
        return None

    return start_year



def apply_copyright_to_file(orig, tf):

    start_year = find_start_year(orig)
    p = pathlib.Path(orig)

    if start_year is None:
        command = 'git status %s' % orig
        (returncode, std_out, std_err) = run_command(command)

        if returncode != 0:
            print('ERROR: %s has git log error (might be due to not committing into git).\n return code=%d \n std_out=%s\n std_err=%s' % (p.absolute(), returncode, std_out, std_err))
            print('ERROR: %s has git stat error.\n return code=%d \n std_out=%s\n std_err=%s' % (p.absolute(), returncode, std_out, std_err))
            return FORMAT_ERROR_CONTINUE

        git_status = std_out
        if len(git_status) == 0:
            print('ERROR: %s has git log error (might be due to not committing into git).\n return code=%d \n std_out=%s\n std_err=%s' % (p.absolute(), returncode, std_out, std_err))
            print('ERROR: %s is not in git and is not marked for addition (has no status). Unable to set first appearance date.' % p.absolute())
            return FORMAT_ERROR_CONTINUE

        if b"new file:" not in git_status:
            print('ERROR: %s has git log error (might be due to not committing into git).\n return code=%d \n std_out=%s\n std_err=%s' % (p.absolute(), returncode, std_out, std_err))
            print('ERROR: %s is not in git and is not marked for addition. Unable to set first appearance date.' % p.absolute())
            return FORMAT_ERROR_CONTINUE

        start_year = datetime.datetime.now().year

    # Apply correct legal header
    text = []
    with open(orig, 'rb') as file_orig:
        for i, line in enumerate(file_orig, 1):
            try:
                text.append(line.decode('utf-8'))
            except UnicodeDecodeError as e:
                print('File: {}, Line: {}, Offset: {}, {}'.format(os.path.abspath(orig), i, e.start, e.reason))
                return FORMAT_ERROR_ABORT

    (filtered_status, filtered_text) = filter_old_copyright_notice(orig, text)
    final_text = apply_new_copyright_notice(filtered_text, start_year, orig)

    with open(tf, 'w', encoding='ascii', errors='ignore') as tmp_file:
        tmp_file.write('\n'.join(final_text) + '\n')
    shutil.copymode(orig, tf)
    return FORMAT_SUCCESSFUL if filtered_status else FORMAT_ERROR_CONTINUE


def filter_old_copyright_notice(orig, text):
    filtered_text = []

    in_copyright = False

    status = True
    line_number = 0
    for line in text:
        line_number += 1
        if in_copyright:
            if end_copyright_line(line):
                in_copyright = False

            continue

        if start_copyright_line(line):
            in_copyright = True
            continue

        # split the string so that leaba_format.py would be able to format itself
        if 'to' + 'dox' in line.lower():
            p = pathlib.Path(orig)
            print('%s:%d: ERROR: contains TODO%s' % (p.absolute(), line_number, 'X'))
            status = False
        filtered_text.append(line.rstrip())

    return (status, filtered_text)


def start_copyright_line(line):
    # split the string so that leaba_format.py would be able to format itself
    return line.find('BEGIN' + '_' + 'LEGAL') != -1


def end_copyright_line(line):
    # split the string so that leaba_format.py would be able to format itself
    return line.find('END' + '_' + 'LEGAL') != -1


def apply_new_copyright_notice(text, start_year, file):
    file = os.path.basename(file)
    copyright_notice = get_copyright_notice(file, start_year)

    if len(text) == 0:
        return copyright_notice

    injection_point = 0

    if re.search(hashtag_comment_regex, file) and \
       text[0].startswith('#!'):
        injection_point = 1

    if text[injection_point].strip() != '':
        copyright_notice.append('')

    final_text = text[0:injection_point] + copyright_notice + text[injection_point:]

    return final_text


def get_copyright_notice(file, start_year):
    if re.search(cstyle_comment_regex, file):
        comment_mark = '//'

    if re.search(hashtag_comment_regex, file):
        comment_mark = '#'

    notice_lines = []

    year_text = '%d-current' % start_year

    for line in notice:
        line = line.replace('YEAR_PLACEHOLDER', year_text)
        notice_lines.append(('%s %s' % (comment_mark, line)).rstrip())

    return notice_lines


def reformat_file(orig, td, global_config_file):
    if os.path.isabs(orig):
        orig_rel = os.path.relpath(orig, os.path.commonpath([orig, os.path.abspath(td)]))
    else:
        orig_rel = orig
    tf = os.path.join(td, orig_rel)

    os.makedirs(os.path.dirname(tf), exist_ok=True)
    pep8_config_file = global_config_file
    src_path = os.path.split(orig)
    dst_path = os.path.split(tf)
    sdk_root_path = pathlib.Path(__file__).parent.parent.absolute()
    while src_path[1]:
        if os.path.exists(os.path.join(src_path[0], ".clang-format")
                          ) and not os.path.exists(os.path.join(dst_path[0], ".clang-format")):
            shutil.copy2(os.path.join(src_path[0], ".clang-format"), dst_path[0])
        if os.path.exists(os.path.join(src_path[0], ".pep8")) and not pep8_config_file:
            pep8_config_file = os.path.join(src_path[0], ".pep8")
            shutil.copy2(os.path.join(src_path[0], ".pep8"), dst_path[0])			
        src_path = os.path.split(src_path[0])
        dst_path = os.path.split(dst_path[0])

    if not pep8_config_file:
        # concat the SDK root dir with the default pep8 file
        pep8_config_file = sdk_root_path.joinpath(".pep8").as_posix()

    format_status = FORMAT_SUCCESSFUL
    if args.notice:
        format_status = apply_copyright_to_file(orig, tf)
        if format_status == FORMAT_ERROR_ABORT:
            return False
    else:
        shutil.copy2(orig, tf)

    command = None
    if re.search(clang_filetype_regex, tf):
        command = 'clang-format -i %s' % tf
    elif re.search(autopep_filetype_regex, tf):
        pep8_extra_args = ""
        with open(tf) as f:
            content = f.readlines()
            for line in content:
                if line[0] == "#":
                    if "pep8_extra_args" in line:
                        pep8_extra_args = line.split('"')[1]
                        break
                else:
                    # stop after parsing comment and blank lines
                    if line.rstrip().lstrip() != "":
                        break
        print(".", end="", flush=True)
        command = '%s -m autopep8 -a -a -a -a --global-config %s %s -i %s ' \
                  % (os.getenv('PYTHON_BIN'), pep8_config_file, pep8_extra_args, tf)
    if command is not None:
        status = os.system(command)
        if status != 0:
            print('ERROR: exit status: %d for command: %s' % (status, command))
            exit(1)

    current = open(orig, encoding='ascii', errors='ignore').read()
    correct = open(tf, encoding='ascii', errors='ignore').read()

    if current == correct:
        # os.remove(tf)
        return (format_status == FORMAT_SUCCESSFUL)

    if args.verify_only:
        p = pathlib.Path(orig)
        print('ERROR: %s needs to be processed by leaba_format.py Please run: make apply-format' % p.absolute())
        return False

    if os.path.islink(orig):
        print("file %s is symlink, skipping..." % orig)
        return (format_status == FORMAT_SUCCESSFUL)

    print('%s reformatted by leaba_format.py' % orig)
    shutil.move(tf, orig)

    return (format_status == FORMAT_SUCCESSFUL)


def reformat_all(args):
    if args.notice:
        read_notice(args.notice)

    reformat_files = collect_files(args.files, args.dirs)
    if len(reformat_files) == 0:
        print("No files to reformat for %s%s" % (' '.join(args.files), ' '.join(args.dirs)))
        return 0

    bad_files_count = 0

    if args.tmpdir is None:
        td = tempfile.mkdtemp(dir='.')
    else:
        td = args.tmpdir

    for path in reformat_files:
        reformat_status = reformat_file(path, td, args.global_config_file)
        if not reformat_status:
            bad_files_count += 1

        if args.tmpdir is None:
            os.remove(tf)

    if args.tmpdir is None:
        shutil.rmtree(td)

    return bad_files_count


def verify_npl_api(args):
    files = [f for f in collect_files(args.files, args.dirs) if f.endswith('.npl') and not any([exclude_dir in f for exclude_dir in args.npl_api_exclude_dirs])]
    for orig in files:
        if orig.endswith(args.npl_api_filter):
        # Verify that all non-constant fields in tables have aliases. (for api file)
            with open(orig) as f:
                for line_num, line in enumerate(f, start=1):
                    if not re.search('^\s*\/\/', line) and not re.search('^\s*\/\*', line) and not re.search('=', line):
                        if re.search(':\s*ternary', line) or re.search(':\s*lpm', line) or re.search(':\s*exact', line):
                            var = line.split(':')[0]
                            if '.' in var and 'udk' not in var:
                                print('ERROR: file: %s doesn\'t comply with npl coding standards, manual changes needed' % (orig))
                                print('ERROR: file: %s line: %d npl table alias missing in reads' % (orig, line_num))
                                exit(1)
                        elif re.search('^\s*writes ', line) and '.' in line.split(';')[0]:
                            print('ERROR: file: %s doesn\'t comply with npl coding standards, manual changes needed' % (orig))
                            print('ERROR: file: %s line: %d npl table alias missing in writes' % (orig, line_num))
                            exit(1)
        elif not orig.endswith(args.npl_api_static_filter):
        # Verify that no tables other than compund and pack tables are defined in file. (for non api file or static file)
                with open(orig) as f:
                    in_table, balanced, table_line_num = False, 0, 0
                    for line_num, line in enumerate(f, start=1):
                        if re.search('^\s*table ', line) and not re.search('#COMPOUND', line):
                            in_table, table_line_num = True, line_num
                        if in_table:
                            for c in line:
                                if c == '/':
                                    break
                                elif c == '{':
                                    balanced += 1
                                elif c == '}':
                                    balanced -= 1
                        if re.search('^\s*type\s*:\s*PACK\s*;', line):
                            in_table, balanced, table_line_num = False, 0, 0
                        if in_table and balanced == 0:
                            print('ERROR: file: %s doesn\'t comply with npl coding standards, manual changes needed' % (orig))
                            print('ERROR: file: %s line: %d npl table location error' % (orig, table_line_num))
                            exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Apply formatting to headers and source files.')
    parser.add_argument('-t', '--tmpdir', dest='tmpdir', action='store', default=None, help='Directory for temporary file(s).')
    parser.add_argument('-f', '--file', dest='files', action='append', default=[], help='Apply notice to a single file.')
    parser.add_argument('-d', '--directory', dest='dirs', action='append', default=[],
                        help='Apply notice to all matching files in a directory.')
    parser.add_argument('-l', '--legal-notice', dest='notice', action='store', default=None, help='Copyright notice file to apply.')
    parser.add_argument('-v', '--verify-only', dest='verify_only', action='store_true', default=False,
                        help='Verify files match format requirements but do not reformat.')
    parser.add_argument('--npl-api-filter', dest='npl_api_filter', action='store', default=None,
                    help='npl api file filter.')
    parser.add_argument('--npl-api-static-filter', dest='npl_api_static_filter', action='store', default=None,
                    help='npl static tables file filter.')
    parser.add_argument('--npl-api-exclude-dirs', dest='npl_api_exclude_dirs', action='append', default=[],
                    help='excluded dirs for decouple npl api enforcement.')
    parser.add_argument('-g', '--global-config', dest='global_config_file', action='store', default='',
                    help='pep8 global config file, default ~/.config/pep8')
    args = parser.parse_args()

    if args.npl_api_filter and args.npl_api_static_filter:
        verify_npl_api(args)

    if not args.files and not args.dirs:
        print('Error: either file or directory have to be specified.')
        exit(1)

    status = reformat_all(args)
    exit(status)
