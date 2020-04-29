import requests
import lxml
import math
import re
from bs4 import BeautifulSoup
import json


pages = 2456
cves = []
for page in range(pages):
    print(f'Page: {page}')
    html = requests.get(f'https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page={page+1}&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=1&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=122751&sha=0cfd1c6feb7980a3cdce726ead01bc1d6297aaef')
    soup = BeautifulSoup(html.text, features='html.parser')
    table_by_row = soup.find(id='vulnslisttable').find_all("tr")
    table_by_row = table_by_row[1::2]
    #print(table_by_row[0])
    for row in table_by_row:
        #print(row.find_all('a')[1].contents)
        try:
            cves.append((row.find_all('a')[1].contents[0], row.find_all('a')[2].contents[0]))
        except:
            continue

mapping = {}
for item in cves:
    #print(item)
    if item[1] in mapping.keys():
        mapping[item[1]].append(item[0])
    else:
        mapping[item[1]] = [item[0]]
#print(mapping)

with open('mapping.json', 'w') as f:
    json.dump(mapping, f, indent=2)
