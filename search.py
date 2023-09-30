from flask import Blueprint, render_template, request, Markup
import requests
import re
import plotly.graph_objs as go
import ast

api_search = Blueprint('search', __name__)
jvn_list = ["jvndb_2023.csv", "jvndb_2022.csv","jvndb_2021.csv"]

@api_search.route("/search", methods=['GET', 'POST'])
def search():
    table ='<table border="1"><tr><th>ID</th><th>title</th><th>CVSSv3</th><th>CVSSv2</th></tr>'
    table_all = '<table border="1"><tr><th>ID</th><th>title</th><th>CVSSv3</th><th>CVSSv2</th></tr>'
    #脅威度別
    table_C = table_H = table_M = table_L =  table_N = table
    #攻撃区分：ネットワーク(N)、隣接(A)、ローカル(L)、物理(P)
    area_N = area_A = area_L = area_P = table
    #脅威度別かつ攻撃区分：ネットワーク(N)、隣接(A)、ローカル(L)、物理(P)
    area_CN = area_HN = area_MN = area_LN = area_NN = table
    area_CA = area_HA = area_MA = area_LA = area_NA = table
    area_CL = area_HL = area_ML = area_LL = area_NL = table
    area_CP = area_HP = area_MP = area_LP = area_NP = table

    base = table + '</table>'
    cvssv2_list = []
    cvssv3_list = []
    cvssv2_float = []
    cvssv3_float = []

    hit = 0
    unit = 0

    keyword = request.args.get('keyword',default='')
    vendor = request.args.get('vendor',default='')

    if keyword == '' and vendor == '':
        return render_template('index.html')
    
    for jvn_file in jvn_list :
        data = open(jvn_file, "r", encoding="utf-8")
        contents = data.read()
        data.close()

        #変更ここから
        items = contents.splitlines()
        for i in items:
            item = i.split(',.,')
            link = item[0]
            sec_identifier = item[1]
            title = item[2]
            item_vendor = item[3]
            item_vendor = ast.literal_eval(item_vendor)
            cvssv3 = item[4]
            cvss3_av_matches = item[5]
            cvssv2 = item[6]
            av_matches = item[7]
        #ここまで
        # kaiseki
            if keyword == '' or keyword in title:
                if vendor == '' or any(j in vendor for j in item_vendor):
                    table_all = table_all + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                    hit = hit + 1
                    #cvssのリスト化
                    if cvssv2 != '-':
                        cvssv2_list.append(cvssv2)
                        cvssv2_cmp = float(cvssv2)
                    if cvssv3 != '-':
                        cvssv3_list.append(cvssv3)
                        cvssv3_cmp = float(cvssv3)

                        #攻撃区分：ネットワーク(N)
                        if cvss3_av_matches == "['N']":
                            area_N = area_N + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            if cvssv3_cmp >= 9.0:
                                area_CN = area_CN + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 7.0:
                                area_HN = area_HN + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 4.0:
                                area_LN = area_LN + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 0.1:
                                area_MN = area_MN + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            else:
                                area_NN = area_NN + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        #攻撃区分：隣接(A)
                        if cvss3_av_matches == "['A']":
                            area_A = area_A + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            if cvssv3_cmp >= 9.0:
                                area_CA = area_CA + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 7.0:
                                area_HA = area_HA + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 4.0:
                                area_LA = area_LA + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 0.1:
                                area_MA = area_MA + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            else:
                                area_NA = area_NA + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title+ '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        #攻撃区分：ローカル(L)
                        if cvss3_av_matches == "['L']":
                            area_L = area_L + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            if cvssv3_cmp >= 9.0:
                                area_CL = area_CL + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 7.0:
                                area_HL = area_HL + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 4.0:
                                area_LL = area_LL + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 0.1:
                                area_ML = area_ML + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            else:
                                area_NL = area_NL + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        #攻撃区分：物理(P)
                        if cvss3_av_matches == "['P']":
                            area_P = area_P + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            if cvssv3_cmp >= 9.0:
                                area_CP = area_CP + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 7.0:
                                area_HP = area_HP + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 4.0:
                                area_LP = area_LP + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            elif cvssv3_cmp >= 0.1:
                                area_MP = area_MP + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                            else:
                                area_NP = area_NP + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'

                        #深刻度別テーブル
                        if cvssv3_cmp >= 9.0:
                            table_C = table_C + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        elif cvssv3_cmp >= 7.0:
                            table_H = table_H + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        elif cvssv3_cmp >= 4.0:
                            table_M = table_M + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        elif cvssv3_cmp >= 0.1:
                            table_L = table_L + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                        else:
                            table_N = table_N + '<tr><td><a href="'+ link +'">' + sec_identifier + '</a></td><td>' + title+ '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'

    table_all = table_all + '</table>'
    #脅威度別
    table_C, table_H, table_M, table_L, table_N = [desk + '</table>' for desk in (table_C, table_H, table_M, table_L, table_N)]
    #攻撃区分：ネットワーク(N)、隣接(A)、ローカル(L)、物理(P)
    area_N, area_A, area_L, area_P = [desk + '</table>' for desk in (area_N, area_A, area_L, area_P)]
    #脅威度別かつ攻撃区分：ネットワーク(N)、隣接(A)、ローカル(L)、物理(P)
    area_CN, area_HN, area_MN, area_LN, area_NN = [desk + '</table>' for desk in (area_CN, area_HN, area_MN, area_LN, area_NN)]
    area_CA, area_HA, area_MA, area_LA, area_NA = [desk + '</table>' for desk in (area_CA, area_HA, area_MA, area_LA, area_NA)]
    area_CL, area_HL, area_ML, area_LL, area_NL =[desk + '</table>' for desk in (area_CL, area_HL, area_ML, area_LL, area_NL)]
    area_CP, area_HP, area_MP, area_LP, area_NP = [desk + '</table>' for desk in (area_CP, area_HP, area_MP, area_LP, area_NP)]


    if table_all == base:
        return render_template('error.html')

    #cvssをstr型からfloat型に変更
    for data_2 in cvssv2_list:
        cvssv2_float.append(float(data_2))
    for data_3 in cvssv3_list:
        cvssv3_float.append(float(data_3))

    #cvss総数カウント 
    total2 = [0, 0, 0, 0]
    total3 = [0, 0, 0, 0]
    for i in cvssv2_float:
        if i >= 9.0:
            total2[0] += 1
        elif i >= 7.0:
            total2[1] += 1
        elif i >= 4.0:
            total2[2] += 1
        else:
            total2[3] += 1
    for i in cvssv3_float:
        if i >= 9.0:
            total3[0] += 1
        elif i >= 7.0:
            total3[1] += 1
        elif i >= 4.0:
            total3[2] += 1
        else:
            total3[3] += 1
    
    #cvssの合計を表示する円グラフを作成
    labels = ["緊急", "重要", "警告", "注意", "なし意"]
    values = total3
    trace = go.Pie(labels=labels, values=values)
    # レイアウト定義
    layout = go.Layout(
        title='深刻度別割合'
    )
    fig = go.Figure(data=[trace], layout=layout)
    # グラフを表示
    graph = fig.to_html(full_html=False, default_height=500, default_width=500)

    #受け取る値：すべて(all)、緊急(C)、重要(H)、警告(M)、注意(L)
    threat = request.form.get('threat',default='')
    #受け取る値：すべて(all)、ネットワーク(N)、隣接(A)、ローカル(L)、物理(P)
    area = request.form.get('area',default='')

    if threat == 'all':
        table_content = {
            'all': table_all,
            'N': area_N,
            'A': area_A,
            'L': area_L,
            'C': area_P
        }.get(area, area_P)
    elif threat == 'C':
        table_content = {
            'all': table_C,
            'N': area_CN,
            'A': area_CA,
            'L': area_CL,
            'C': area_CP
        }.get(area, area_CP)
    elif threat == 'H':
        table_content = {
            'all': table_H,
            'N': area_HN,
            'A': area_HA,
            'L': area_HL,
            'C': area_HP
        }.get(area, area_HP)
    elif threat == 'M':
        table_content = {
            'all': table_M,
            'N': area_MN,
            'A': area_MA,
            'L': area_ML,
            'C': area_MP
        }.get(area, area_MP)
    elif threat == 'L':
        table_content = {
            'all': table_L,
            'N': area_LN,
            'A': area_LA,
            'L': area_LL,
            'C': area_LP
        }.get(area, area_LP)
    else:
        table_content = table_all
    return render_template('search.html', response=Markup(table_content), graph=graph, threat=threat, area=area)