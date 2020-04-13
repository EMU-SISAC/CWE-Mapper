import requests
import lxml
import math
import re
from bs4 import BeautifulSoup
import json

def getPages(soup):
    paging = soup.find_all('b')[-1].contents[0]
    #print(paging)
    pages = math.ceil(int(paging)/50)
    print(f'Pages = {pages}')
    return pages
    
def getVulns(url, counter):
    html = requests.get(url).text
    soup = BeautifulSoup(html, features='html.parser')
    pages = getPages(soup)
    cves = []
    for page in range(pages):
        html = requests.get(f'https://www.cvedetails.com/vulnerability-list.php?page={pages+1}&cweid={counter}')
        table_by_row = soup.find(id='vulnslisttable').find_all("tr")
        table_by_row = table_by_row[1::2]
        #print(table_by_row[0])
        for row in table_by_row:
            #print(row.find_all('a')[1].contents)
            cves.append(row.find_all('a')[1].contents[0])
    return cves

mapping = {}        
for counter in range(808):
    if counter == 0:
        continue 
    print(f'CWE: {counter}')
    url = f'https://www.cvedetails.com/vulnerability-list/cweid-{counter}/vulnerabilities.html'
    mapping[counter] = getVulns(url, counter)
print(mapping)
with open('mapping.json', 'w') as f:
    json.dump(mapping, f)
