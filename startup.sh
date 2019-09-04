#! /bin/bash
sudo apt install python -y
sudo curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-260.0.0-linux-x86_64.tar.gz
sudo tar zxvf google-cloud-sdk-260.0.0-linux-x86_64.tar.gz google-cloud-sdk
sudo ./google-cloud-sdk/install.sh --quiet
source .bashrc

sudo apt install python-pip
pip install google-cloud-logging

project=$1
useraccount=$2
window=$3
sudo mkdir -p /home/tmp
cd /home/tmp
sudo rm *.*
sudo curl -OL https://raw.githubusercontent.com/minzhuogoogle/gke_lab_monitor/master/lab_mon.py
sudo sync
sudo chmod +x lab_mon.py

sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project $project -window $window -user $useraccount -forever &
sudo /home/tmp/lab_mon.py -logger_name cloudaudit.googleapis.com%2Factivity -project $project -window $window -user $useraccount 

