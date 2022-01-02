import re
from time import sleep

import requests


def get_spf_record(domain_name):
    burp0_url = "https://www.kitterman.com:443/spf/getspf3.py"
    burp0_headers = {"Connection": "close", "Pragma": "no-cache", "Cache-Control": "no-cache",
                     "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36",
                     "Origin": "https://www.kitterman.com", "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                     "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                     "Sec-Fetch-Dest": "document", "Referer": "https://www.kitterman.com/spf/validate.html",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"}
    burp0_data = {"serial": "fred12", "domain": domain_name}
    response = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
    result = str(re.search(r"No valid SPF record found.", response.text))
    if result:
        write_file(domain_name)
        return "Vulnerable, {0}".format(result)

    result = str(re.search(r"~all", response.text))

    if result:
        write_file(domain_name)
        return "Vulnerable, {0}".format(result)

    result = str(re.search(r"~ALL", response.text))

    if result:
        write_file(domain_name)
        return "Vulnerable, {0}".format(result)

    return "Not Vulnerable"


def write_file(domain_name):
    with open("output_spf.txt", "a") as f:
        f.write(domain_name+" Vulnerable\n")
        sleep(1)


if __name__ == '__main__':
    with open("domain_to_scan.txt", "r") as f:
        domain_list = f.readlines()

    for domain_name in domain_list:
        print(get_spf_record(domain_name.strip()))
