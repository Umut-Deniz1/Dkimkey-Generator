from __future__ import print_function
import os
import subprocess
import sys
import tempfile
from flask import *

app = Flask(__name__)


# how strong are our keys?
BITS_REQUIRED = 1024

# what openssl binary do we use to do key manipulation?
OPENSSL_BINARY = '/usr/bin/openssl'


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

def main(d):
    key_name = d
    key_type = 'rsa'
    private_key_file = key_name + '.key'
    dns_file = key_name + '.dns'

    priv = GenRSAKeys(private_key_file)
    pub = ExtractRSADnsPublicKey(private_key_file, dns_file)

    keys = {
        "public":pub,
        "private":priv
    }
    return keys

    


@app.route("/")
def home():
    d = request.args.get("d")
    return main(d)

if __name__ == '__main__':
    app.run(debug=True)
