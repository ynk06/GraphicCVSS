import os
import requests
import re
import schedule
from time import sleep

NUM_PAGES = 2023

def task():
    for i in range(2021, NUM_PAGES + 1):
        FILENAME = f"jvndb_{i}"
        URL = f"https://jvndb.jvn.jp/ja/rss/years/{FILENAME}.rdf"
        
        response = requests.get(URL)
        print(URL+" : download")
        data = open(FILENAME + ".csv","w")
        if response.status_code == 200:
            items = re.findall(r'<item [^>]*>(.*?)<\/item>', response.text, re.DOTALL)
            for item in items:
                sec_identifier = re.findall(r'<sec:identifier>(.*?)<\/sec:identifier>', item)
                title = re.findall(r'<title>(.*?)<\/title>', item)
                link = re.findall(r'<link>(.*?)<\/link>', item)
                item_vendor = re.findall(r'vendor="(.*?)"', item)
                cvssv3 = re.findall(r'sec:cvss version="3.0" score="(\d+\.\d+)"', item)
                cvssv2 = re.findall(r'sec:cvss version="2.0" score="(\d+\.\d+)"', item)
                cvssv3 = cvssv3[0] if cvssv3 else "-"
                cvssv2 = cvssv2[0] if cvssv2 else "-"
                area = re.findall(r'vector="(?:AV:([A-Z])|CVSS:3\.0/AV:([A-Z]))', item)
                av_matches = [match[0] for match in area if match[0]]
                cvss3_av_matches = [match[1] for match in area if match[1]]
                sec_identifier = sec_identifier[0] if sec_identifier else "-"
                item_vendor[0] if item_vendor else item_vendor.append('')
                cwe_title = re.findall(r'id="(CWE-[A-Za-z0-9]+)"', item)
                cwe_title[0] if cwe_title else cwe_title.append('')
                announcement_day = re.findall(r'<dcterms:issued>(\d{4}-\d{2}-\d{2}).*?</dcterms:issued>', item)
                update_day = re.findall(r'<dcterms:modified>(\d{4}-\d{2}-\d{2}).*?</dcterms:modified>', item)
                data.write(link[0] + ',.,' + sec_identifier + ',.,' + title[0] + ',.,' + str(item_vendor) + ',.,' + cvssv3 + ',.,' + str(cvss3_av_matches) + ',.,' + cvssv2 + ',.,' + str(av_matches) + ',.,'  + str(cwe_title) + ',.,' + announcement_day[0] + ',.,' + update_day[0] + '\n')
        else:
           print(f"Failed to download {URL}")
           continue
        data.close()
    print("finished") 

schedule.every().days.at("04:00").do(task)
task()

while True:
    schedule.run_pending()
    sleep(1)