from flask import Blueprint, render_template, request, Markup
import requests
import re
import plotly.graph_objs as go
import ast

cwe_search = Blueprint('cwe_search', __name__)
jvn_list = ["jvndb_2023.csv", "jvndb_2022.csv","jvndb_2021.csv"]

@cwe_search.route("/cwe", methods=['GET', 'POST'])
def cwe_find():
    table ='<table border="1"><tr><th>ID</th><th>title</th><th>CVSSv3</th><th>CVSSv2</th></tr>'
    table_all = '<table border="1"><tr><th>ID</th><th>title</th><th>CVSSv3</th><th>CVSSv2</th></tr>'
    base = table + '</table>'

    cwe_full = request.args.get('cwe',default='')
    vendor = request.args.get('vendor',default='')

    pattern = r'(CWE-[A-Za-z0-9]+)'
    cwe_tmp = re.findall(pattern, cwe_full)
    cwe_id = cwe_tmp[0]

    for jvn_file in jvn_list :
        data = open(jvn_file, "r", encoding="utf-8")
        contents = data.read()
        data.close()
        # kaiseki
        items = contents.splitlines()

        for i in items:
            item = i.split(',.,')
            link = item[0]
            sec_identifier = item[1]
            title = item[2]
            item_vendor = ast.literal_eval(item[3])
            cvssv3 = item[4]
            cvss3_av_matches = item[5]
            cvssv2 = item[6]
            av_matches = item[7]
            cwe_title = ast.literal_eval(item[8])

            if len(cwe_title) != 0:
                if any(j in cwe_id for j in cwe_title) and vendor == '' or any(j in vendor for j in item_vendor):
                    table_all = table_all + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'

    table = table_all + '</table>'
    table_all = table_all + '</table>'
    if table_all == base:
        return render_template('error.html')
    
    return render_template('cwe.html', keyword=cwe_id, vendor=vendor, response=Markup(table_all))
