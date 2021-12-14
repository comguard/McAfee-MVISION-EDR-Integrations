# MVISION EDR Threats (Monitoring)

This is a script to retrieve threats and detections from MVISION EDR (Monitoring Dashboard).

The following steps describe an example to run the provided script as a service under a Linux Operating system (CentOS).
The script requires various parameters to execute incl. MVISION EDR Tenant Region, ClientId and ClientSecret.

There are multiple ways in securely provide credentials to the script. 
- Password Vaults like Vault from Hashicorp (https://www.vaultproject.io/) or python vaults to store credentials securely. 
- Using a hidden .env file to store credentials and provide credentials in form of environment variables to the script.

The latter example will be described below.

**Important** 

Client_ID and Client_Secrets can get generated with the [mvision_edr_creds_generator.py](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations/blob/master/mvision_edr_creds_generator.py) script posted in the main [repository](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations).

## Configuration

1. Place the script in an accessible directory e.g.

```sh
usage: python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -L <MAX RESULTS> -MS <MINIMUM SEVERITY> -S <SENDER EMAIL> -T <RECIPIENT EMAIL> -M <MAIL SERVER IP> -MP <MAIL SERVER PORT>


optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --trace {True,False}, -T {True,False}
                        EXPERIMENTAL: Enrich threat information with trace data
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
