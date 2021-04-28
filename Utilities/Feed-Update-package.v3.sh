#!/bin/bash
# This script was built to run on the CbEDR 7.4.2. cb-enterprise services need to be running at the time of starting this script.
set -e
today=$(date +%d%b%Y)
clear
echo "     Welcome! This script simply updates the CB Threat Feeds then packages for distribution"
sleep 5
echo "syncing threat feeds - wait 5 min ..."
sudo /usr/share/cb/virtualenv/bin/python -m cb.maintenance.job_runner --master -q feed_sync --full-sync
sleep 1m
echo "syncing threat feeds - wait 4 min ..."
sleep 1m
echo
echo "syncing threat feeds - wait 3 min ..."
sleep 1m
echo
echo "syncing threat feeds - wait 2 min ..."
sleep 1m
echo
echo "syncing threat feeds - wait 1 min ..."
sleep 1m
echo
git clone https://github.com/carbonblack/cb-airgap-feed.git /opt/cb-airgap-feed$today
echo "exporting Threat Feeds for Airgap"
cd /opt/cb-airgap-feed$today
#
# Adding code and variable to airgap_feed.py script for it to adapt to custom WebUI port
sed -i 's/443/" + webPORT + "/g' airgap_feed.py
#
ex airgap_feed.py <<eof
11 insert

# Setting variable for webport

pattern = "NginxWebApiHttpPort"

file = open("/etc/cb/cb.conf", "r")
for line in file:
        if re.search(pattern, line):
                webPORT = line.split("=")[1]

.
xit
eof
#
sudo sudo /usr/share/cb/virtualenv/bin/python airgap_feed.py export -f /root/cbfeeds-$today
echo
echo
echo "packaging threat feeds and yum cache"
cd /root/
sudo tar --selinux -czf cbfeeds-$today.tar.gz cbfeeds-$today
echo
echo
echo
echo "CbEDR Airgap Feed package is Ready, run the following command from your host to get it"
ip=$(sudo ip addr | grep inet | grep -v inet6 | grep -v '127.0.0' | cut -d "/" -f1 | awk '{print $2}')
echo "        'scp root@$ip:/root/cbfeeds-$today.tar.gz .'      "
echo
echo
echo
read -n 1 -r -s -p $'Press anykey to continue...'
