#!/usr/bin/env python3
# Written by mohlcyber v.0.9 (06.08.2021)
# Script to retrieve all threats from the monitoring dashboard

import sys
import getpass
import requests
import time
import logging
import json
import os
import smtplib

from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta
from logging.handlers import SysLogHandler
from string import Template
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class EDR():
    def __init__(self):
        self.iam_url = 'iam.mcafee-cloud.com/iam/v1.1'
        if args.region == 'EU':
            self.base_url = 'soc.eu-central-1.mcafee.com'
        elif args.region == 'US-W':
            self.base_url = 'soc.mcafee.com'
        elif args.region == 'US-E':
            self.base_url = 'soc.us-east-1.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'soc.ap-southeast-2.mcafee.com'
        elif args.region == 'GOV':
            self.base_url = 'soc.mcafee-gov.com'

        self.logging()

        self.session = requests.Session()
        self.session.verify = True

        creds = (args.client_id, args.client_secret)
        
        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        self.cache_fname = 'cache.log'
        if os.path.isfile(self.cache_fname):
            cache = open(self.cache_fname, 'r')
            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')

            now = datetime.astimezone(datetime.now())
            hours = int(str(now)[-5:].split(':')[0])
            minutes = int(str(now)[-5:].split(':')[1])

            self.last_pulled = (last_detection + timedelta(hours=hours, minutes=minutes, seconds=1)).strftime(self.pattern)
            self.logger.debug('Cache exists. Last detection date UTC: {0}'.format(last_detection))
            self.logger.debug('Pulling newest threats from: {0}'.format(self.last_pulled))
            cache.close()

            self.last_check = (last_detection + timedelta(seconds=1)).strftime(self.pattern)
        else:
            self.logger.debug('Cache does not exists. Pulling data from last 14 days.')
            self.last_pulled = (datetime.now() - timedelta(days=14)).strftime(self.pattern)
            self.last_check = (datetime.now() - timedelta(days=14)).strftime(self.pattern)

        self.limit = '2000'
        self.auth(creds)

    def logging(self):
        # setup the console logger
        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel.upper())
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def auth(self, creds):
        try:
            payload = {
                'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
                'grant_type': 'client_credentials',
                'audience': 'mcafee'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))
            
            if res.ok:
                token = res.json()['access_token']
                self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
                self.logger.debug('AUTHENTICATION: Successfully authenticated.')
            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_threats(self):
        try:
            epoch_before = int(time.mktime(time.strptime(self.last_pulled, self.pattern)))

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities

            res = self.session.get(
                'https://api.{0}/ft/api/v2/ft/threats?sort=-lastDetected&filter={1}&from={2}&limit={3}'
                .format(self.base_url, json.dumps(filter), str(epoch_before * 1000), str(self.limit)))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))
            
            if res.ok:
                self.logger.debug('SUCCESS: Successful retrieved threats.')

                res = res.json()
                if len(res['threats']) > 0:
                    cache = open(self.cache_fname, 'w')
                    cache.write(res['threats'][0]['lastDetected'])
                    cache.close()

                    for threat in res['threats']:
                        detections = self.get_detections(threat['id'])
                        threat['url'] = 'https://ui.' + self.base_url + '/monitoring/#/workspace/72,TOTAL_THREATS,{0}'\
                            .format(threat['id'])
                        
                        # Set severity of detection
                        if args.minimum_severity is not None:
                            severity = threat["severity"]
                            severityINT = 0
                            if severity == "s0":
                                severity = "INFO"
                                severityINT = 0
                            if severity == "s1":
                                severity = "VERY LOW"
                                severityINT = 1
                            if severity == "s2":
                                severity = "LOW"
                                severityINT = 2
                            if severity == "s3":
                                severity = "MEDIUM"
                                severityINT = 3
                            if severity == "s4":
                                severity = "HIGH"
                                severityINT = 4
                            if severity == "s5":
                                severity = "CRITICAL"
                                severityINT = 5
                            
                            if args.minimum_severity > severityINT:
                                continue
                            
                        hostnames = []
                        ipAddresses = []

                        for detection in detections:
                            threat['detection'] = detection

                            self.logger.info(json.dumps(threat))
                            
                            hostnames.append(threat["detection"]["host"]["hostname"])
                            ipAddresses.append(threat["detection"]["host"]["netInterfaces"][0]["ip"])
                            
                        if args.mail_ip is not None:
                            mailPort = 25
                            if args.mail_port is not None:
                                mailPort = args.mail_port
                            else:
                                self.logger.info('Mail server port is not defined, using default 25')
                            
                            newThreat = json.dumps(threat)
                            
                            hostnamesFormatted = ""
                            first = True
                            for hostname in hostnames:
                                hostnamesFormatted += hostname
                                if not first:
                                    hostnamesFormatted += ", "
                                    first = False
                            
                            first = True   
                            ipAddressesFormatted = ""
                            for ipAddress in ipAddresses:
                                ipAddressesFormatted += ipAddress
                                if not first:
                                    ipAddressesFormatted += ", "
                                    first = False
                            
                            email_subject = "McAfee EDR: Alert with " + severity + " severity from " + hostnamesFormatted
                            
                            msg = MIMEMultipart()
                            message_template = self.read_email_template('./email_template.txt')
                            message = message_template.substitute(NAME = threat["name"], TYPE=threat["type"], SEVERITY=severity, HOSTNAME=hostnamesFormatted, IP=ipAddressesFormatted, URL=threat["url"])
                            
                            msg['From'] = args.sender
                            msg['To'] = ", ".join(args.recipient)
                            msg['Subject'] = email_subject
                            
                            msg.attach(MIMEText(message, 'plain'))
                            
                            smtp = smtplib.SMTP(args.mail_ip, mailPort)
                            smtp.sendmail(args.sender, args.recipient, msg.as_string())
                            self.logger.info('Successfully sent email')
                            smtp.quit
                        
                        else:
                            self.logger.error('Please provide the Mail server IP')
                            exit()

                else:
                    self.logger.info('No new threats identified. Exiting. {0}'.format(res))
                    exit()
            else:
                self.logger.error('Error in edr.get_threats(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except smtplib.SMTPException:
            self.logger.error('Unable to send email')
        
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_detections(self, threatId):
        try:
            last_detected = datetime.strptime(self.last_check, self.pattern)

            res = self.session.get('https://api.' + self.base_url + '/ft/api/v2/ft/threats/{0}/detections'
                                   .format(threatId))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                detections = []
                for detection in res.json()['detections']:
                    first_detected = datetime.strptime(detection['firstDetected'], '%Y-%m-%dT%H:%M:%SZ')

                    if first_detected >= last_detected:
                        detections.append(detection)

                return detections
            else:
                self.logger.error('Error in retrieving edr.get_detections(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_trace(self, maGuid, traceId):
        try:
            res = self.session.get('https://api.' + self.base_url +
                                   '/historical/api/v1/traces/main-activity-by-trace-id?maGuid={0}&traceId={1}'
                                   .format(maGuid, traceId))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                return res.json()
            else:
                return {}

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def read_email_template(self, filename):
        with open(filename, 'r', encoding='utf-8') as template_file:
            template_file_content = template_file.read()
        return Template(template_file_content)

if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -LL <LOG_LEVEL> -MS <MINIMUM SEVERITY> -SE <SENDER EMAIL> -T <RECIPIENT EMAIL> -M <MAIL SERVER IP> -MP <MAIL SERVER PORT>"""
    title = 'McAfee EDR Python API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US-W', 'US-E', 'SY', 'GOV'])

    parser.add_argument('--client_id', '-C',
                        required=True, type=str,
                        help='MVISION EDR Client ID')

    parser.add_argument('--client_secret', '-S',
                        required=False, type=str,
                        help='MVISION EDR Client Secret')
    
    parser.add_argument('--loglevel', '-LL',
                        required=False, type=str, choices=['INFO', 'DEBUG'], default='INFO',
                        help='Set Log Level')
    
    parser.add_argument('--minimum-severity', '-MS',
                        required=False, type=int,
                        help='Minimum severity of alert', choices=[0, 1, 2, 3, 4, 5])

    parser.add_argument('--sender', '-SE',
                        required=True, type=str,
                        help='Sender email address')
    
    parser.add_argument('--recipient', '-T',
                        required=True, action='append',
                        help='Recipient email address. If more than one, use -T multiple times')
    
    parser.add_argument('--mail-ip', '-M',
                        required=False, type=str,
                        help='SMTP relay server IP address')
    
    parser.add_argument('--mail-port', '-MP',
                        required=False, type=int,
                        help='SMTP relay server port')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(prompt='MVISION EDR Client Secret: ')

    edr = EDR()
    edr.get_threats()
