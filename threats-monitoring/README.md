# McAfee MVISION EDR Threats (Monitoring)

## mvision_edr_threats_email

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard) and send them via email. The script requires a username, password, sender's and recepient's email addresses, mail server IP address and limit to query the threats. The script will write a file called cache.log to safe the last threat detection date. In case of internet connection issue or script execution issue it makes sure to pull all newest threat detections.

Further the script allows to specify SMTP port (default is 25) and minimum severity of threats, that will be processed.

1. Place the script in an accessible directory e.g.

```sh
usage: python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -L <MAX RESULTS> -MS <MINIMUM SEVERITY> -S <SENDER EMAIL> -T <RECIPIENT EMAIL> -M <MAIL SERVER IP> -MP <MAIL SERVER PORT>


optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --limit LIMIT, -L LIMIT
                        Maximum number of returned items
  --minimum-severity {0,1,2,3,4,5}, -MS {0,1,2,3,4,5}
                        Minimum event severity to send notification
  --sender SENDER_EMAIL, -S SENDER_EMAIL
                        Sender email address
  --recipient RECIPIENT_EMAIL, -T RECIPIENT_EMAIL
                        Recipient email address. If more than one, use -T multiple times.
  --mail-ip MAIL_SERVER_IP, -M MAIL_SERVER_IP
                        SMTP relay server IP address
  --mail-port MAIL_SERVER_PORT, -MP MAIL_SERVER_PORT
                        SMTP relay server port
```

## mvision_edr_threats_quarantine

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard), and automatically quarantine the hosts. The script requires a username, password and a limit to query the threats. The script will write a file called cache.log to safe the last threat detection date. In case of internet connection issue or script execution issue it makes sure to pull all newest threat detections.

Further the script allows to specify minimum severity of the threats, that will be processed.

Usage:

```sh
usage: python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -L <MAX RESULTS> -MS <MINIMUM SEVERITY>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --limit LIMIT, -L LIMIT
                        Maximum number of returned items
  --minimum-severity {0,1,2,3,4,5}, -MS {0,1,2,3,4,5}
                        Minimum event severity to send notification
```

## mvision_edr_threats

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard) and send it via syslog. The script requires a username, password and a limit to query the threats. The script will write a file called cache.log to safe the last threat detection date. In case of internet connection issue or script execution issue it makes sure to pull all newest threat detections.

Further the script allows to retrieve additional details about the threat itself (-D / --details flag). This includes traces of the affected systems. This feature is experimental.

Usage:

```sh
usage: python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -L <MAX RESULTS> -S <SYSLOG IP> -SP <SYSLOG PORT>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --details {True,False}, -D {True,False}
                        EXPERIMENTAL: Enrich threat information with trace data
  --limit LIMIT, -L LIMIT
                        Maximum number of returned items
  --syslog-ip SYSLOG_IP, -S SYSLOG_IP
                        Syslog IP Address
  --syslog-port SYSLOG_PORT, -SP SYSLOG_PORT
                        Syslog Port
```