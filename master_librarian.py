import os
import argparse
from util import utils
import subprocess
import shlex

def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = True, help = 'Name of output type for logs(txt or csv)')
    args = parser.parse_args()
    return args.types

types = arguments()
cmd="/usr/bin/pkg-config"
output=subprocess.check_output([cmd,"--list-all"])
pkgs = output.splitlines()

utils.banner_start()

for elem in pkgs:
    tmp=elem.decode()
    words=tmp.split(' ')
    pkg_name=str(words[0])
    output=subprocess.check_output([cmd,"--print-provides",shlex.quote(pkg_name)])
    tmp=str(output.decode())
    tmp=tmp.replace("= ","")
    tmp=tmp.replace("\n","")
    utils.search_nist(tmp,3,types)

    
