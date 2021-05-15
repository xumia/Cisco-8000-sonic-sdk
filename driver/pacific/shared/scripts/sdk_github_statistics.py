# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import requests
import datetime
import os
import smtplib
from email.mime.text import MIMEText
import sys
import json
import time

# This script is executed by SDK_github_statistics_mailer Jenkins job
# from location /big_share2/pacific/user/prudic/sdk_github_statistics.py
# In order to work it must have files "users.json" and "users_presence.json"
# with write permission in directiry where it is located.


class GithubStatistics:
    def __init__(self):
        # Tuple of repositories that will be searched.
        self.repositories = ("Leaba/sdk",)
        repositories = ("repo:" + repo for repo in self.repositories)
        # String made from tuple of repositories used for searching.
        repositories = ' '.join(repositories)
        self.url = "https://cto-github.cisco.com/api/v3/search/issues"
        self.headers_to_request = {'Authorization': "token ab273ccbc01bbd54eeaf61f4111acf0a3f541d7f"}
        self.query_base = f"{repositories} type:pr"
        self.parameters = {'page': 1, 'per_page': 100}

        # Calculate time search strings.
        time_now = datetime.datetime.now()
        time_delta = datetime.timedelta(days=7)
        a_week_ago = time_now - time_delta
        self.a_week_ago_str = a_week_ago.strftime("%Y-%m-%d")
        self.time_now_str = time_now.strftime("%Y-%m-%d")

        path_prefix = os.path.dirname(os.path.realpath(__file__))
        self.logfile = os.path.join(path_prefix, 'statistics.log')
        self.users_set_file = os.path.join(path_prefix, 'users.json')
        self.users_presence = os.path.join(path_prefix, "users_presence.json")

        # If user didn't have any activity after user_max_presence days,
        # the user will be removed from set of users in file users.json
        self.user_max_presence = 800

    def get_pull_requests_info(self, paramets: str) -> list:
        self.parameters['q'] = " ".join((self.query_base, paramets))
        return self.get_request(self.url, self.headers_to_request, self.parameters)

    def get_all_pull_requests(self, params_) -> dict:
        self.parameters['q'] = " ".join((self.query_base, params_))
        self.parameters['page'] = 1
        issues = list()
        page = 1
        # Collect pull requests from all pages.
        while True:
            self.parameters['page'] = page
            info = self.get_request(self.url, self.headers_to_request, self.parameters)
            if not info['items']:
                break
            issues += info['items']
            if info['total_count'] < self.parameters['per_page']:
                break
            page += 1
        return issues

    def get_prs_from_last_week(self, last_week_filter, params_) -> dict:
        filter_string = last_week_filter + ":" + \
            self.a_week_ago_str + ".." + self.time_now_str
        self.parameters['q'] = " ".join((self.query_base, params_, filter_string))
        return self.get_request(self.url, self.headers_to_request, self.parameters)

    def get_request(self, url, headers_, params_={}, fast=False) -> dict:
        response = requests.get(url, headers=headers_, params=params_)
        if not response.ok:
            error_message = (f"\nERROR: {self.url} returned error code {response.status_code}\n"
                             f"parameters are {params_}\n"
                             f"headers are {headers_}\n")
            self.log_error(error_message)
            sys.exit(1)
        # Must sleep here. Otherwise server will send 403 error code after max number(approximately 30)
        # of consecutive requests without timeout. That limit could change so it is safest
        # to sleep after every request. But some urls don't require timouts.
        if not fast:
            time.sleep(2)
        return response.json()

    def gather_raa_users(self) -> dict:
        """ Gather users from pull requests that are either (r)equested for review,
        (a)signee or (a)uthor. """
        # Get data of all open pull requests.
        pull_requests = list()
        self.parameters['state'] = "open"
        for repo in self.repositories:
            url = f"https://cto-github.cisco.com/api/v3/repos/{repo}/pulls"
            page = 1
            while True:
                self.parameters['page'] = page
                prs = self.get_request(url, self.headers_to_request, self.parameters, True)
                if not prs:
                    break
                pull_requests += prs
                if len(prs) < self.parameters['per_page']:
                    break
                page += 1
        del self.parameters['state']

        # Make "users" dictionary.
        users = self.rearrange_pull_requests(pull_requests)
        del pull_requests

        # Update set of all users.
        users_set_old = set()
        # There have to be users.json file whith read and write permissions
        if os.path.exists(self.users_set_file):
            with open(self.users_set_file, "r") as f:
                users_set_old = set(json.load(f))
        all_users_set = set(users.keys()).union(users_set_old)
        del users_set_old

        # Find users reviewing pull requests.
        active_users, err_msg = self.get_reviews_last_week(users, all_users_set)
        active_users.union(set(users.keys()))

        # Update last presence of users stored in file.
        self.update_users_presence(active_users, all_users_set)

        # Write updated set of users to file.
        with open(self.users_set_file, "w") as f:
            json.dump(sorted(all_users_set), f)

        # Get full name of each user.
        base_user_url = "https://cto-github.cisco.com/api/v3/users/"
        for user, info in users.items():
            user_url = base_user_url + user
            response = self.get_request(user_url, self.headers_to_request, fast=True)
            info['full_name'] = response['name']

        return users, err_msg

    def rearrange_pull_requests(self, pull_requests):
        # Make dictionary called "users".
        users = dict()
        """
        Search opened pull requests and record assignees,
        authors and requested reviewers.
        Dictionary "users" looks like this:
        {'user1' : { 'author' : {4909 : { 'title' : "Title of pull request 4909",
                                          'html_url' : "https//cto-github.cisco.com/.../4909",
                                 4914 : { 'title' : "Title of 4914 pull request",
                                          'html_url' : "https//...",
                     'assignee' : {...},
                     'reviews_requested' : {...},
                     'full_name' : "Doc Adams"},
         'user2' : { 'asignee' : {...},
                     'approved' : {...},
                     'full_name' : "..."},
         'user3' : { 'reviews_requested' : {...},
                     'full_name' : "..."},
         .
         .
         .}
        """
        for pull_request in pull_requests:
            author = pull_request['user']['login']
            pr = dict()
            pr['title'] = pull_request['title']
            pr['html_url'] = pull_request['html_url']
            users.setdefault(author, dict())
            users[author].setdefault('author', dict())
            users[author]['author'].update({pull_request['number']: pr})
            for assignee in pull_request['assignees']:
                assignee_name = assignee['login']
                users.setdefault(assignee_name, dict())
                users[assignee_name].setdefault('assignee', dict())
                users[assignee_name]['assignee']\
                    .update({pull_request['number']: pr})
            for reviewer in pull_request['requested_reviewers']:
                reviewer_name = reviewer['login']
                users.setdefault(reviewer_name, dict())
                users[reviewer_name].setdefault('reviews_requested', dict())
                users[reviewer_name]['reviews_requested']\
                    .update({pull_request['number']: pr})

        return users

    def update_users_presence(self, active_users, old_set):
        """ Structure of users_presence dictionary:
           {user1: 2020-04-04,
            user2: 2020-03-03,
            ...}"""
        # This file must exist!
        if os.path.exists(self.users_presence):
            with open(self.users_presence, "r") as f:
                present_users = json.load(f)
            # Update time for active users.
            for user in active_users:
                present_users.setdefault(user, "")
                present_users[user] = self.time_now_str
            # If some user didn't have activity since user_max_presence days ago,
            # It will be delted from users.json file.
            users_to_remove = set()
            for user, last_presence in present_users.items():
                lp = datetime.datetime.strptime(last_presence, "%Y-%m-%d")
                time_now = datetime.datetime.now()
                if (time_now - lp).days > self.user_max_presence:
                    users_to_remove.add(user)
            for user in users_to_remove:
                del present_users[user]
                old_set.discard(user)
        else:
            # How first file was created.
            present_users = dict()
            for user in old_set:
                present_users[user] = self.time_now_str
        with open(self.users_presence, "w") as f:
            json.dump(present_users, f)

    def get_reviews_last_week(self, users, all_users):
        reviewing_data = dict()
        reviewed_data = dict()
        all_concerning = self.get_all_pull_requests((f"-closed:<={self.a_week_ago_str}"
                                                     " review:approved"
                                                     " review:changed_requested"))
        all_set = set()
        for pr in all_concerning:
            all_set.add(pr['number'])
        del all_concerning
        active_users = set()
        for user in all_users:
            user_rev_issues = self.get_all_pull_requests((f"-closed:<={self.a_week_ago_str}"
                                                          f" reviewed-by:{user}"
                                                          f" -author:{user}"))
            for rev_issue in user_rev_issues:
                active_users.add(user)
                all_set.discard(rev_issue['number'])
                if not rev_issue['closed_at']:
                    reviewing_data.setdefault(user, dict())
                    reviewing_data[user].update({rev_issue['number']:
                                                 {'title': rev_issue['title'],
                                                  'html_url': rev_issue['html_url']}})
                else:
                    reviewed_data.setdefault(user, dict())
                    reviewed_data[user].update({rev_issue['number']:
                                                {'title': rev_issue['title'],
                                                 'html_url': rev_issue['html_url']}})
        err_msg = ""
        if all_set:
            err_msg = (f"Warning: These pull requests: {all_set},\n"
                       "have reviewers that are not in users.json set.\n"
                       "Please add those reviewers to file "
                       f"{os.path.abspath(self.users_set_file)}")
            self.log_error(err_msg)

        # Update users dictionary with last week's reviewing requests.
        for user, data in reviewing_data.items():
            users.setdefault(user, dict())
            users[user].setdefault('reviewing', dict())
            users[user]['reviewing'].update({number: info for number, info in data.items()})
        for user, data in reviewed_data.items():
            users.setdefault(user, dict())
            users[user].setdefault('reviewed', dict())
            users[user]['reviewed'].update({number: info for number, info in data.items()})
        del reviewing_data
        del reviewed_data

        return active_users, err_msg

    def log_error(self, error_message):
        formatted_message = "\n\n" + self.time_now_str + " " +\
            datetime.datetime.now().strftime("%H:%M:%S") +\
            error_message + "\n"
        with open(self.logfile, "a") as f:
            f.write(formatted_message)
        print(formatted_message, file=sys.stderr)


class GHStatisticsHTML:
    def __init__(self):
        self.counts_html_list = str()
        self.users_html = str()

    def make_html_list_of_prs(self, pull_requests):
        time_now = datetime.datetime.now()
        # Day is in the format dat/month/year
        date = time_now.strftime("%d %B %Y")
        # Make html list
        self.counts_html_list += (
            "<h1>Pull requests weekly report</h1>\n"
            f"<h2>Date {date}</h2>\n"
            "<h3>Number of pull requests:</h3>\n"
            "<ul>\n"
            f"<li>open: {pull_requests['open']['total_count']}</li>\n"
            f"<li>closed: {pull_requests['closed']['total_count']}</li>\n"
            f"<li>merged: {pull_requests['merged']['total_count']}</li>\n"
            "</ul>\n<p><br></p>"
            # Add counts from last week to html
            "<h3>Last week's statistics of pull requests</h3>\n"
            "<ul>\n"
            "<li>Created last week: "
            f"{pull_requests['created_last_week']['total_count']}</li>\n"
            "<li>Closed last week: "
            f"{pull_requests['closed_last_week']['total_count']}</li>\n"
            "<li>Merged last week: "
            f"{pull_requests['merged_last_week']['total_count']}</li>\n"
            "</ul>\n"
            "<hr><p><br></p>\n")

    def write_html_table_row(self, info, key_, header) -> str:
        self.users_html += ("<tr>\n"
                            "<th class=\"key_\">" + header + "</th>\n"
                            f"<td class=\"number\">{len(info[key_])}</td>\n"
                            "<td class=\"info\">\n")
        for number, data in sorted(info[key_].items(), reverse=True):
            self.users_html += ("<p>" + f"<a title=\"{data['html_url']}\""
                                f"href=\"{data['html_url']}\">" +
                                str(number) + ": " + data['title'] +
                                "</a><br></p>\n")
        self.users_html += "</td></tr>\n"

    def make_html_table_for_users(self, users):
        self.users_html = "<h2> Role of users in open requests: </h2>"
        # Sort by full name.

        def sort_by_full_name(name): return name['full_name']
        for info in sorted(users.values(), key=sort_by_full_name):
            self.users_html += "<caption>" + info['full_name'] + ":</caption>\n"
            self.users_html += "<table>\n"
            if info.get('assignee'):
                self.write_html_table_row(info, 'assignee', "Assignee")
            if info.get('author'):
                self.write_html_table_row(info, 'author', "Author")
            if info.get('reviews_requested'):
                self.write_html_table_row(info,
                                          'reviews_requested',
                                          "Requested review")
            if info.get('reviewing'):
                self.write_html_table_row(info, 'reviewing', "Reviewed")
            if info.get('reviewed'):
                self.write_html_table_row(info, 'reviewed', "Reviewed closed")
            self.users_html += "</table><p><br></p>\n\n"

    def make_entire_html(self, err_msg) -> str:
        the_whole_html = ("<!DOCTYPE html> <html>\n"
                          "<head> <style>\n"
                          "table,th,td {\n"
                          "border: 1px solid black;\n"
                          "border-collapse: collapse;\n"
                          "margin-left:20px;\n"
                          "}\n"
                          "table {\n"
                          "width:950px;\n"
                          "}\n"
                          "th, td {\n"
                          "padding:10px;\n"
                          "}\n"
                          "th.key {\n"
                          "width:8.3%;\n"
                          "}\n"
                          "td.number {\n"
                          "width:0.9%;\n"
                          "text-align:center;\n"
                          "}\n"
                          "td.info {\n"
                          "width:90.8%;\n"
                          "}\n"
                          "</style> </head>\n"
                          "<body>" + self.counts_html_list + self.users_html +
                          "<p>" + err_msg + "</p>" +
                          "\n</body> </html>")
        return the_whole_html


def send_mail(log_error_function, html_str):
    sendto = []
    if len(sys.argv) > 1:
        sendto = sys.argv[1].replace(" ", "").split(',')
    is_outside_cisco = False in map(lambda t: t.endswith('@cisco.com'), sendto)
    if is_outside_cisco:
        log_error_function(f"Was trying to send E-mail to an address outside Cisco. Aborting! (sento = {sendto})\n")
        sys.exit(2)

    to = ','.join(sendto)
    title = "Pull requests statistics"
    if len(sendto) > 0:
        msg = MIMEText(html_str, 'html')
        msg['Subject'] = title
        msg['From'] = "jenkins@cisco.com"
        msg['To'] = to
        msg['Date'] = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        s = smtplib.SMTP('localhost')
        s.send_message(msg)
        s.quit()
    else:
        log_message = (f"\nSending mail\ntitle: {title}\n"
                       f"to:{to}\nbody: \n{html_str}\n--------------\n")
        log_error_function(log_message)


def main():
    # Search for open pull requests.
    gs = GithubStatistics()
    pull_requests = dict()
    pull_requests['open'] = gs.get_pull_requests_info("is:open")
    pull_requests['closed'] = gs.get_pull_requests_info("is:closed")
    pull_requests['merged'] = gs.get_pull_requests_info("is:merged")

    # Search for open pull requests created since a week ago until now.
    pull_requests['created_last_week'] = gs.get_prs_from_last_week("created", "")
    # Search for closed pull requests created since a week ago until now.
    pull_requests['closed_last_week'] = gs.get_prs_from_last_week("closed", "is:closed")
    # Search for merged pull requests created since a week ago until now.
    pull_requests['merged_last_week'] = gs.get_prs_from_last_week("merged", "is:merged")

    # Make html from gathered data.
    ghs_html = GHStatisticsHTML()
    ghs_html.make_html_list_of_prs(pull_requests)
    # Free memory that won't be used eny more.
    del pull_requests

    # Get information from open pull requests.
    users, err_msg = gs.gather_raa_users()
    ghs_html.make_html_table_for_users(users)
    del users

    final_html = ghs_html.make_entire_html(err_msg)
    send_mail(gs.log_error, final_html)
    del final_html
    del gs
    del ghs_html


if __name__ == "__main__":
    main()
