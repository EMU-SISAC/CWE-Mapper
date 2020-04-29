import csv, re, json

examples = []
CVE = re.compile("CVE-\d\d\d\d-\d\d\d\d")
with open('1000.csv','r', newline = '') as csvfile:
    reader = csv.reader(csvfile)
    for line in reader:
        examples.append((line[0],re.findall(CVE,line[17])))
   
with open('mapping.json', 'r') as jsonfile:
    mapping = json.load(jsonfile)
    for example in examples:
        if example[0] == 'CWE-ID':
            continue
        elif example[0] not in mapping.keys():
            mapping[example[0]] = [example[1]]
        else:
                mapping[example[0]].extend(example[1])
            
    
    with open('combined-mapping.json', 'w') as f:
        json.dump(mapping, f, indent=2)
    
    
'''for ex in examples:
        print(f'Parsing CVEs in CWE {ex[0]}')
        for cve in ex[1]:
            #print(f"\n\n\nChecking for {cve} in {mapping[ex[0]]}")
            if cve in mapping[ex[0]]:
                print(f"{cve} already exists.")'''