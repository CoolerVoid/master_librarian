import os
import argparse
from util import utils
import subprocess
import shlex
import time

def arguments():
    parser = argparse.ArgumentParser(description = utils.banner())
    parser.add_argument('-t', '--type', action = 'store', dest = 'types',default='txt',required = True, help = 'Name of output type for logs(txt or csv)')
    args = parser.parse_args()
    return args.types

def start_librarian():
    types = arguments()
    cmd="/usr/bin/pkg-config"
    output=subprocess.check_output([cmd,"--list-all"])
    pkgs = output.splitlines()
    utils.banner_start()
    counter=0

    for elem in pkgs:
        tmp=elem.decode()
        words=tmp.split(' ')
        pkg_name=str(words[0])
        output=subprocess.check_output([cmd,"--print-provides",shlex.quote(pkg_name)])
        tmp=str(output.decode())
        tmp=tmp.replace("= ","")
        tmp=tmp.replace("\n","")
        utils.search_nist(tmp,3,types)
        if counter == 3:
            time.sleep(3)
            counter=0
        counter+=1

def main():
    try:
        start_librarian()
    except Exception as e:
        print(" log error : "+str(e))
        exit(0)

if __name__=="__main__":
    main()
