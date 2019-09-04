#! /bin/bash
gcloud config set account 17851170406-compute@developer.gserviceaccount.com
sudo mkdir -p /home/tmp
cd /home/tmp
sudo rm *.py
sudo curl -OL https://raw.githubusercontent.com/minzhuogoogle/gke_lab_monitor/master/lab_mon.py
sudo chmod +x lab_mon.py
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user mzhuo@google.com
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user mzhuo@google.com -gclient
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user min.zhuo@gmail.com
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user min.zhuo@gmail.com -gclient

sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user mzhuo@google.com -forever  &
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user mzhuo@google.com -gclient -forever &
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user min.zhuo@gmail.com -forever &
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project csp-gke-231805 -window 7 -user min.zhuo@gmail.com -gclient -forever &
