#!/bin/python3
import requests as req
import json, os, argparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()

"""
    reverse IP, Subdomain Enumerate, Etc.
    code by Dinar, fb.com/dinar1337
    free of use
"""


class YaGabut(object):

    def __init__(self, domain='http://google.com/', email='jancok@gmail.com', result_path='result'):
        if 'http' in domain:
            domain = domain.split('/')[2]
        self.domain = domain
        self.url = 'https://www.threatcrowd.org'
        self.headers = {
            'Host' : 'www.threatcrowd.org',
            'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0'
        }
        self.email = email
        self.result_path = result_path
        if not os.path.isdir(self.result_path):
            os.mkdir(self.result_path)

    def is_ip(self):
        ip = self.domain.split('.')
        if len(ip) > 3 or len(ip) == 4:
            validate_int = self.domain.replace('.','').isnumeric()
            if validate_int:
                return True
            else:
                return False
        return False

    def subdomain(self):
        get_data = req.get(f"{self.url}/searchApi/v2/domain/report/?domain={self.domain}",
                        headers=self.headers,
                        timeout=10,
                        verify=False
                        )
        if 'subdomain' in get_data.text:
            json_loads = json.loads(get_data.text)
            total = len(json_loads['subdomains'])
            print("Total Subdomain : {}".format(total))
            for sub in json_loads['subdomains']:                
                self.save(sub, newline=True, filename="subdomain.txt")
            return True
        return False
    
    def ip_from_domain(self, reverseIp=False):
        get_data = req.get(f"{self.url}/searchApi/v2/domain/report/?domain={self.domain}",
                        headers=self.headers,
                        timeout=10,
                        verify=False
                        )
        if 'resolutions' in get_data.text:
            json_loads = json.loads(get_data.text)
            total = len(json_loads['resolutions'])
            print("Total Ip From Domain : {}".format(total))
            for ip in json_loads['resolutions']:
                self.save(ip['ip_address'], newline=True, filename="ip.txt")
                if reverseIp:
                    self.reverseIp(target=ip['ip_address'])
            
    def email_report(self):
        get_data = req.get(f"{self.url}/searchApi/v2/email/report/?email={self.email}",
                        headers=self.headers,
                        timeout=10,
                        verify=False
                        )
        json_loads = json.loads(get_data.text)
        if '0' in str(json_loads['response_code']):
            print('Cant get information from Email : {}'.format(self.email))
            return False
        elif '1' in str(json_loads['response_code']):
            if 'domains' in get_data.text:
                total = len(json_loads['domains'])
                print('Containt {} Domains from Email {}'.format(total, self.email))
                for domain in json_loads['domains']:
                    self.save(domain, newline=True, filename="domainFromEmail.txt")
                return True
        else:
            print('cant get Anything from email : {}'.format(self.email))
            return False
    
    def email_info_by_domain(self):
        get_data = req.get(f"{self.url}/searchApi/v2/domain/report/?domain={self.domain}",
                        headers=self.headers,
                        timeout=10,
                        verify=False
                        )
        json_loads = json.loads(get_data.text)
        if '1' in str(json_loads['response_code']):
            if 'emails' in get_data.text:
                total = len(json_loads['emails'])
                if total == 0 or total == 1:
                    if json_loads['emails'][0] == "":
                        print('Cant get email from domain {}'.format(self.domain))
                        return False
                print('Total {} email from domain {}'.format(total, self.domain))
                for email in json_loads['emails']:
                    if email == "":
                        print("")
                    else:
                        self.email = email
                        self.email_report()
            else:
                print('Cant get email from domain {}'.format(self.domain))
        else:
            print('Cant get email from domain {}'.format(self.domain))

    def reverseIp(self, target=None):
        if target is None:
            target = self.domain
        get_data = req.get(f"{self.url}/searchApi/v2/ip/report/?ip={target}",
                headers=self.headers,
                timeout=10,
                verify=False
                )
        json_loads = json.loads(get_data.text)
        if '1' in str(json_loads['response_code']):
            total_domain = len(json_loads['resolutions'])
            print('Get {} domain from {}'.format(total_domain, target))
            for res in json_loads['resolutions']:
                self.save(str(res['domain']), newline=True, filename="reverseip.txt")
        
    def save(self, data, newline=True, filename="results.txt"):
        if not os.path.isdir(f"{self.result_path}/{self.domain}"):
            os.mkdir(f"{self.result_path}/{self.domain}")
        opens = open(f"{self.result_path}/{self.domain}/{filename}",'a')
        if newline:
            opens.write(data + '\n')
        else:
            opens.write(data)
        opens.close()


def main():
    parser = argparse.ArgumentParser(description='reverse IP, Subdomain Enumerate, Etc')
    parser.add_argument("--target", help="target site", required=True)
    parser.add_argument("--reverseip", help="reverse ip from ip", action='store_true', required=False)
    parser.add_argument("--domain-from-email", help="get registered domain by that email address target", action='store_true', required=False)
    parser.add_argument("--subdomain", help="get subdomain from domain target", action='store_true', required=False)
    parser.add_argument("--email-from-domain", help="get email address by domain target", action='store_true', required=False)
    args = parser.parse_args()
    exs = YaGabut(domain=args.target)
    if args.reverseip:
        if exs.is_ip():
            exs.reverseIp()
        else:
            exs.ip_from_domain(reverseIp=True)
    elif args.domain_from_email:
        exs.email_report()
    elif args.email_from_domain:
        exs.email_info_by_domain()
    elif args.subdomain:
        exs.subdomain()

if __name__=='__main__':
    main()
