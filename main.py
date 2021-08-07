from __future__ import print_function
import os
import subprocess
import sys
import tempfile
import argparse
import hashlib
import base64
from flask import Flask, request
import re

app = Flask(__name__)
BITS_REQUIRED = 1024
OPENSSL_BINARY = '/usr/bin/openssl'
d_list = [".com.tr", ".biz.tr", ".info.tr", ".org.tr", ".av.tr", ".pol.tr", ".bel.tr", ".mil.tr", ".bbs.tr", ".k12.tr", ".edu.tr", ".name.tr", ".net.tr", ".gov.tr", ".com", ".net", ".org", ".aero", ".asia", ".biz", ".cat", ".coop", ".edu", ".gov", ".info", ".int", ".jobs", ".mil", ".mobi", ".museum", ".name", ".pro", ".tel",".travel",".news",".xyz"]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def GenRSAKeys(private_key_file):
    eprint('generating ' + private_key_file)
    subprocess.check_call([OPENSSL_BINARY, 'genrsa', '-out', private_key_file,
                           str(BITS_REQUIRED)])
    
    # command = "rm {}".format(private_key_file)
    # subprocess.run(command, shell=True, capture_output=True)

    with open(private_key_file, "r") as f:
        line = ""
        for i in f.readlines():
            line += i 
        key = line
    return key
    


def ExtractRSADnsPublicKey(private_key_file, dns_file):
    eprint('extracting ' + private_key_file)
    working_file = tempfile.NamedTemporaryFile(delete=False).name
    subprocess.check_call([OPENSSL_BINARY, 'rsa', '-in', private_key_file,
                           '-out', working_file, '-pubout', '-outform', 'PEM'])
    try:
        with open(working_file) as wf:
            y = ''
            for line in wf.readlines():
                if not line.startswith('---'):
                    y += line
                    
            output = ''.join(y.split())
    finally:
        os.unlink(working_file)
    
    pub = "v=DKIM1; k=rsa; h=sha256; p={0}".format(output)
    return pub

def main():
    if request.args.get("s") and request.args.get("d"):
        d = request.args.get("d")
        s = request.args.get("s")

        key_name = "{}.{}".format(s,d)
        #key_type = 'rsa'
        private_key_file = key_name + '.key'
        dns_file = key_name + '.dns'

        priv = GenRSAKeys(private_key_file)
        pub = ExtractRSADnsPublicKey(private_key_file, dns_file)

        keys = {
            "A-Record":[
            {key_name:"151.101.1.195"},
            {key_name:"151.101.65.195"},
            {"mail.{}".format(key_name):"92.45.23.132"}
            ],
            "TXT": [
               { key_name: "v=spf1 include:valuezon.com -all"},
               { key_name: "spf2.0/pra include:valuezon.com -all"}
            ],
            "MX": [
                {key_name : "mail.{}".format(key_name)}
            ],
            "_dmarc.{}".format(key_name):"v=DMARC1; p=none; fo=1; rua=mailto:admin@{}; ruf=mailto:admin@{}; rf=afrf; pct=100".format(key_name,key_name),
            "{}._domainkey.{}".format(s,key_name):pub,
            s:priv,
            "dkim-selector": "{}".format(s)
        }
        return keys
    elif request.args.get("d"):
        d = request.args.get("d")

        clean_domain = ""
        for i in d_list:
            if i in d:
                clean_domain = d.replace(i, "")
                break
            else:
                sayi = re.findall(r"\.",d)
                if len(sayi) > 1:
                    x = re.search(r"\.\w+[.]\w+", d) 
                else:
                    x = re.search(r"\.\w+", d)
                d_list.append(x.group())


        key_name = d
        #key_type = 'rsa'
        private_key_file = key_name + '.key'
        dns_file = key_name + '.dns'

        priv = GenRSAKeys(private_key_file)
        pub = ExtractRSADnsPublicKey(private_key_file, dns_file)

        keys = {
            "A-Record":[
            {d:"151.101.1.195"},
            {d:"151.101.65.195"},
            {"mail.{}".format(d):"92.45.23.132"}
            ],
             "TXT": [
               { d: "v=spf1 include:valuezon.com -all"},
               { d: "spf2.0/pra include:valuezon.com -all"}
            ],
            "MX": [
                {d : "mail.{}".format(d)}
            ],
            "_dmarc.{}".format(d):"v=DMARC1; p=none; fo=1; rua=mailto:admin@{}; ruf=mailto:admin@{}; rf=afrf; pct=100".format(d,d),
            "{}._domainkey.{}".format(clean_domain,d):pub,
            clean_domain:priv,
            "dkim-selector": "{}".format(clean_domain)
        }
        return keys
    else:
        return {
            "Error":" 'd' is required "
        }

    

@app.route("/")
def home():
    return main()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
