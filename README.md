# gke_lab_monitor
This script checks log in log named as "cloudaudit.googleapis.com%2Factivity" for particular user for the number of past days.
Upon finish the script writes a one-line log to log named as "partner_activities_check" regarding how many logs found. 

The script can be used to check cloud activity for particular user in specified time duration.

#prerequisite
Before running the script make sure to install Google Cloud SDK.
This script needs to import logging library. To install logging library, run:
            pip install google-cloud-logging 

#Download script
curl -OL https://raw.githubusercontent.com/minzhuogoogle/gke_lab_monitor/master/lab_mon.py

# Usage Sample
mzhuo@minzhuo2:~/tmp$ ./lab_mon.py  cloudaudit.googleapis.com%2Factivity  gkeoplabs-hammerspace-1 hammerspace-1@csppartnerlabs.com  7 
Filter used to retrieve log: timestamp>="2019-08-22T00:00:00Z" AND protoPayload.authenticationInfo.principalEmail:hammerspace-1@csppartnerlabs.com
Listing entries for logger cloudaudit.googleapis.com%2Factivity:
Wrote logs to partner_activities_check.


mzhuo@minzhuo2:~/tmp$ ./lab_mon.py partner_activities_check  gkeoplabs-hammerspace-1 all  0 
Filter used to retrieve log: timestamp>="2019-08-29T00:00:00Z"
Listing entries for logger partner_activities_check:
* 2019-08-29T21:22:00.844311+00:00: Found 54 of log for mzhuo@google.com in the project gkeoplabs-hammerspace-1 for the last 7 days
* 2019-08-29T21:22:44.809613+00:00: Found 1 of log for all in the project gkeoplabs-hammerspace-1 for the last 0 days
* 2019-08-29T21:39:03.486306+00:00: For the last 7 days found 54 of log for mzhuo@google.com in the project gkeoplabs-hammerspace-1.
* 2019-08-29T21:41:07.811768+00:00: For the last 7 days found 0 of log for hammerspace-1@csppartnerlabs.com in the project gkeoplabs-hammerspace-1.
* 2019-08-29T21:42:55.449421+00:00: WARNING: For the last 7 days no log  found for hammerspace-1@csppartnerlabs.com in the project gkeoplabs-hammerspace-1.
* 2019-08-29T22:08:05.349760+00:00: WARNING: For the last 7 days no log  found for hammerspace-1@csppartnerlabs.com in the project gkeoplabs-hammerspace-1.


