import requests
from termcolor import colored
import warnings
import json

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
    print(colored('Master librarian v0.3 \n',"yellow")+' Tool to search public vulnerabilities on local libraries\nby CoolerVoid\nSearch pitfalls in operational system local packages\n')

def banner():
    print(colored('Master librarian v0.3 \n',"yellow")+' Tool to search public vulnerabilities on local libraries\nby CoolerVoid')
    print("\nExample: \n\t$ python3 master_librarian.py -t csv\n\t$ python3 master_librarian.py -t txt -l 3\n")

def parser_response_csv(pkg_name,content):
    data = json.loads(content)

    for vuln in data['result']['CVE_Items']:
        cve=vuln['cve']['CVE_data_meta']['ID']
        url="https://nvd.nist.gov/vuln/detail/"+cve
        date=vuln['publishedDate']
        description=vuln['cve']['description']['description_data'][0]['value']
        try:
            cvss2=vuln['impact']['baseMetricV2']['severity']
        except:
            cvss2="NULL"
        try:
            cvss3=vuln['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except:
            cvss3="NULL"
        # use pipes '|' because field description have ',' this can crash parsers
        row=pkg_name+"|"+date+"|"+cve+"|"+url+"|"+cvss2+"|"+cvss3+"|"+description
        with open('librarian_log.csv', 'a+') as f:
            f.write(row+"\n")
        print(row)

def parser_response(content):
    data = json.loads(content)

    for vuln in data['result']['CVE_Items']:
        url="https://nvd.nist.gov/vuln/detail/"+str(vuln['cve']['CVE_data_meta']['ID'])
        print("\n\tURL: "+colored(url,"cyan"))
        print("\tDate: "+vuln['publishedDate'])
        print("\tDescription:"+colored(vuln['cve']['description']['description_data'][0]['value'],"yellow"))
        try:
            print("\tCVSS V2 Risk: "+risk_color(vuln['impact']['baseMetricV2']['severity']))
            print("\tCVSS V3 Risk: "+risk_color(vuln['impact']['baseMetricV3']['cvssV3']['baseSeverity']))
        except:
            print("\tRisk is not defined")
    

def getCPE(cpe,limit):
    if cpe != 0:
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="+cpe+"&resultsPerPage="+str(limit)
        r = requests.get(url)
        if r.status_code == 200:
            return r.text
        else:
            return False
    return False

def fix_cpe_str(str):
    return str.replace('-',':')

def search_nist(pkg_name,types,limit):
    result = getCPE(pkg_name,limit)
    if result:
        if("csv" in types):
            parser_response_csv(pkg_name,result)
        else:
            print(colored(pkg_name,"green"))
            parser_response(result)
