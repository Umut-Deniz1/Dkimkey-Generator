 from __future__ import print_function
import os
import subprocess
import sys
import tempfile
import argparse
import hashlib
import base64
from flask import Flask, request
from flask_cors import CORS
import re
import random

app = Flask(__name__)
CORS(app)
BITS_REQUIRED = 1024
OPENSSL_BINARY = '/usr/bin/openssl'


def valid(*args):
    for variable in args:
        if not type(variable):
            return False
        if variable in ["", " ", None, "None", "undefined", "null"]:
            return False
    return True


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
            line += i.strip('\n') 
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
    if valid(request.args.get("d")):
        d = request.args.get("d") 
    else:
        d = "example.com"
    
    s = request.args.get("s") if valid(request.args.get("s")) else str(random.randrange(100001, 999999))

    key_name = "{}.{}".format(s,d)
    #key_type = 'rsa'
    private_key_file = key_name + '.key'
    dns_file = key_name + '.dns'

    priv = GenRSAKeys(private_key_file)
    pub = ExtractRSADnsPublicKey(private_key_file, dns_file)

    keys = {
        "A":[
            {d:"151.101.1.195"},
            {d:"151.101.65.195"},
            {"mail.{}".format(d):"92.45.23.132"}
        ],
        "TXT": [
            { d: "v=spf1 include:valuezon.com -all"},
            { d: "spf2.0/pra include:valuezon.com -all"},
            { "_dmarc.{}".format(d): "v=DMARC1; p=none; fo=1; rua=mailto:admin@{}; ruf=mailto:admin@{}; rf=afrf; pct=100".format(d,d)},
            { "{}._domainkey.{}".format(s,d):pub},
        ],
        "MX": [
            {d : "mail.{}".format(d)}
        ],
        "DKIM Selector": "{}".format(s),
        "RSA Private Key": priv
    }
    return keys      
    

@app.route("/")
def home():
    return main()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
