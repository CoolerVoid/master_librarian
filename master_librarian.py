import os
import argparse
from util import utils
import subprocess
import shlex
import time

def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = True, help = 'Name of output type for logs(txt or csv)')
    parser.add_argument('-l', '--limit', action = 'store', dest = 'limit',default='3',required = False, help = 'Limit CVEs per pages in nvd NIST search(default is 3)')
    args = parser.parse_args()
    return args.types,args.limit

def start_librarian():
    types,limit = arguments()
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
        utils.search_nist(tmp,types,limit)
    if "csv" in types:
        print("\n\t Please look the CSV logs in file librarian_log.csv")

def main():
    try:
        start_librarian()
    except Exception as e:
        print(" log error : "+str(e))
        exit(0)

if __name__=="__main__":
    main()
