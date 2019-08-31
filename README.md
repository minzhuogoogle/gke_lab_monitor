# Description
This script checks log in log named as "cloudaudit.googleapis.com%2Factivity" for particular user for the number of past days.
Upon finish the script writes a one-line log to log named as "partner_activities_check" regarding how many logs found. 

The script can be used to check cloud activity for particular user in specified time duration.

# Prerequisite
Before running the script make sure to install Google Cloud SDK, please refer to https://cloud.google.com/sdk/docs/quickstart-linux.
This script needs to import logging library. To install logging library, run:
            pip install google-cloud-logging 
            

# Download script
curl -OL https://raw.githubusercontent.com/minzhuogoogle/gke_lab_monitor/master/lab_mon.py

# Usage 
mzhuo@linux-ws:~$ ./lab_mon.py --help
usage: lab_mon.py [-h] [-logger_name LOGGER_NAME] -project PROJECT
                  [-user USER] [-logfilter LOGFILTER] [-window WINDOW]
                  [-serviceacct SERVICEACCT] [-gclient]

optional arguments:
  -h, --help            show this help message and exit
  -logger_name LOGGER_NAME, --logger_name LOGGER_NAME
                        Log Name
  -project PROJECT, --project PROJECT
                        Project ID
  -user USER, --user USER
                        User Name
  -logfilter LOGFILTER, --logfiler LOGFILTER
                        log filter
  -window WINDOW, --window WINDOW
                        number of days to inspect logs
  -serviceacct SERVICEACCT, --serviceacct SERVICEACCT
                        Google Cloud service account
  -gclient, --gclient   flag to use gclient to retrieve log or not


# Sample
mzhuo@linux-ws:~$ ./lab_mon.py -logger_name  cloudaudit.googleapis.com%2Factivity -project  csp-gke-231805 -user  mzhuo@google.com -window 1 -serviceacct logger_reader.json
gcloud auth activate-service-account --key-file=logger_reader.json
Command issued is still running, please wait......
Command is finished.

Activated service account credentials for: [logger-reader@csp-gke-231805.iam.gserviceaccount.com]

Filter used to retrieve log: timestamp>="2019-08-30T00:00:00Z" AND logName:cloudaudit.googleapis.com%2Factivity AND protoPayload.authenticationInfo.principalEmail:mzhuo@google.com 
gcloud logging read 'timestamp>="2019-08-30T00:00:00Z" AND logName:cloudaudit.googleapis.com%2Factivity AND protoPayload.authenticationInfo.principalEmail:mzhuo@google.com ' --project=csp-gke-231805 | grep insertId | wc -l
Command issued is still running, please wait......
Command is finished.
result: 19

gcloud logging write partner_activities_check  "For the last 1 days found 19 of log for mzhuo@google.com in the project csp-gke-231805."  --severity=INFO --project=csp-gke-231805
Command issued is still running, please wait......
Command is finished.
result: 
Created log entry.

# Env Preparation before running script
The following steps was tested on "Linux linux-ws 4.15.0-1036-gcp #38-Ubuntu SMP Mon Jun 24 13:49:05 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux".
 1. Install python 
    sudo apt install python  
 2. Install gcloud sdk
   curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-260.0.0-linux-x86_64.tar.gz
   tar zxvf google-cloud-sdk-260.0.0-linux-x86_64.tar.gz google-cloud-sdk
   ./google-cloud-sdk/install.sh
   source .bashrc
 3. install pip
    sudo apt install python-pip
 4. install  google-cloud-logging
     pip install google-cloud-logging
