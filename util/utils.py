import requests
from termcolor import colored
import warnings
from lxml import html
import xml.etree.ElementTree as treant

warnings.simplefilter("ignore")

def risk_color(risk):
  if "LOW" in risk:
    return colored(risk,"green")
  if "MEDIUM" in risk:
    return colored(risk,"yellow")
  if "HIGH" in risk:
    return colored(risk,"red")
  if "CRITICAL" in risk:
    return colored(risk,"red",attrs=['blink'])

def banner_start():
    print(colored('Master librarian v0.1 \n',"yellow")+' Tool to search public vulnerabilities on local libraries\nby CoolerVoid\nSearch pitfalls in operational system local packages\n')

def banner():
    print(colored('Master librarian v0.1 \n',"yellow")+' Tool to search public vulnerabilities on local libraries\nby CoolerVoid')
    print("\nExample: \n\t$ python3 master_librarian.py -t csv\n\t$ python3 master_librarian.py -t txt\n")

def parser_response_csv(content,limit,csv_str):
    tree = html.fromstring(content)
    desc = tree.xpath("//*[contains(@data-testid, 'vuln-summary')]")
    cve = tree.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
    score = tree.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
    if len(desc) > 0:
        maxLimit = limit  if limit <= len(desc) else len(desc) - 1
        if limit > len(desc):
            maxLimit = len(desc)
        for i in range(0,maxLimit):
            url =("https://nvd.nist.gov/vuln/detail/"+cve[i].text)
            print(csv_str+'|'+str(cve[i].text)+"|"+url+"|"+str(score[i].text)+"|"+str(desc[i].text) )
                                                                                                    

def parser_response(content,limit):
    tree = html.fromstring(content)
    desc = tree.xpath("//*[contains(@data-testid, 'vuln-summary')]")
    cve = tree.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
    score = tree.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
    if len(desc) > 0:
        maxLimit = limit  if limit <= len(desc) else len(desc) - 1
        if limit > len(desc):
            maxLimit = len(desc)
        for i in range(0,maxLimit):
            print ("\t\t" + colored(desc[i].text,"magenta") )
            url =("https://nvd.nist.gov/vuln/detail/"+cve[i].text)
            print ("\t\t" + colored(url,"green") )
            print ("\t\t" + risk_color(score[i].text +"\n") )
    print

def getCPE(cpe):
    if cpe != 0:
        url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query="+cpe+"&search_type=all&isCpeNameSearch=false"
        r = requests.get(url)
        if r.status_code == 200:
            return r.content
        else:
            return False
    return False

def fix_cpe_str(str):
    return str.replace('-',':')

def search_nist(pkg_name,limit,types):
    result = getCPE(pkg_name)
    if result:
        if("csv" in types):
            parser_response_csv(result,limit,pkg_name)
        else:
            print(colored(pkg_name,"green"))
            parser_response(result,limit)
