#!/usr/bin/env python

# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The script is used to check cloud activities log for 
specified user.
"""

import argparse
import time
from datetime import datetime, timedelta, date
from datetime_truncate import truncate
from pytz import timezone
import pytz

from google.cloud import logging

PST_ZONE = timezone('US/Pacific')


def write_entry(logger_name, project, number, user, window):
    """Writes log entries to the given logger."""
    logging_client = logging.Client()

    # This log can be found in the Cloud Logging console under 'Custom Logs'.
    logger = logging_client.logger(logger_name)

    # Make a simple text log

    # Simple text log with severity.
    if number == 0:
         severity_status = "WARNING"
         logger.log_text('WARNING: For the last {} days no log  found for {} in the project {}.'.format(window, user, project[0]), severity=severity_status)
    else:
         severity_status = "INFO"
         logger.log_text('For the last {} days found {} of log for {} in the project {}.'.format(window, number, user, project[0]), severity=severity_status)


    print('Wrote logs to {}.'.format(logger.name))


def list_entries(logger_name, project, user, window):
    """Lists the most recent entries for a given logger."""
    logging_client = logging.Client()
    logger = logging_client.logger(logger_name)
    FILTER = 'protoPayload.authenticationInfo.principalEmail:{}'.format(user)
    mydate = datetime.now(PST_ZONE)
    mydate = mydate -  timedelta(days = window)
    start_date = str(mydate).split(' ')[0]
    if not user == 'all':
        FILTER =  'timestamp>="{}T00:00:00Z" AND protoPayload.authenticationInfo.principalEmail:{}'.format(start_date, user)
    else:
        FILTER =  'timestamp>="{}T00:00:00Z"'.format(start_date)
    print "Filter used to retrieve log: {}".format(FILTER)
    print('Listing entries for logger {}:'.format(logger.name))

    projectlist = []
    projectlist.append(project)
    loglist = None
    loglist = logger.list_entries(projects=projectlist, filter_=FILTER)

    if not loglist:
        print "No log found."
        return
    count = 0
    for entry in loglist:
        timestamp = entry.timestamp.isoformat()
        print('* {}: {}'.format
              (timestamp, entry.payload))
        count += 1
    write_logger_name = "partner_activities_check"
    if not logger_name == write_logger_name:
        write_entry(write_logger_name, projectlist, count, user, window)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'logger_name', help='Logger name', default='global')
    parser.add_argument(
        'project', help='project id', default=None)
    parser.add_argument(
        'user', help='user', default=None)
    parser.add_argument(
        'window', help='number of days to inspect logs', default=None)

    args = parser.parse_args()

    list_entries(args.logger_name, args.project, args.user, int(args.window))
