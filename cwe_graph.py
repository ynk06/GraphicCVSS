from flask import Blueprint, render_template, request
import json
import csv
import os

import pandas as pd
import numpy as np

import csv
from collections import defaultdict
import ast

cwe_graph = Blueprint('cwe_graph', __name__)

SAVE_DIR = "./"
DEMO_DIR = "./"

def csvToDf(csvTemp):
    os.system("nkf --overwrite -w " + csvTemp)
    df = pd.read_csv(csvTemp, encoding="utf-8")

    temp = df.iloc[0, 0].astype(np.float32)
    if np.isnan(temp):
        df = df.drop(df.index[[0]])
        df.reset_index(drop=True, inplace=True)

    # 欠損値を置換
    df = df.fillna(0)

    dateTime = []
    passTime = []

    dateDf = pd.DataFrame({
        'ナンバー [-]': dateTime,
        '年月 [s]': passTime
    })
    df = df.drop(df.columns[[0]], axis=1)

    return df, dateDf

# データフレームをリストに変換
def dfToList(df):
    List = df.T.values.tolist()
    return List

# urlにアクセスしたらindex.htmlを開く
@cwe_graph.route('/cwe_graph')
def top():
    return render_template('cwe_graph.html')

@cwe_graph.route("/upload", methods=['GET', 'POST'])
def upload():
    jvn_list = ["jvndb_2021.csv", "jvndb_2022.csv","jvndb_2023.csv"]
    # 空のリストをキーとする辞書を作成
    lists_dict = {f'list{i}': [] for i in range(1, len(jvn_list) + 1)}
    yearlist_dict = {f'yearlist{i}': [] for i in range(1, len(jvn_list) + 1)}
    datalist = []

    ivendor = []

    vendor = request.form.get('vendor',default='')

    for jvn_file in jvn_list:
        data = open(jvn_file, 'r', encoding="utf-8")
        contents = data.read()
        data.close()

        items = contents.splitlines()
        for i in items:
            item = i.split(',.,')
            item_vendor = item[3]
            item_vendor = ast.literal_eval(item_vendor)
            cwe = item[8]
            if vendor == '' or any(j in vendor for j in item_vendor):
                #年別ファイルのcweをカウント
                #if item_vendor == [vendor]:
                if item_vendor != ['']:
                    ivendor.append(item_vendor)
                    for key in lists_dict:
                        if jvn_file == jvn_list[int(key[-1]) - 1]:
                            lists_dict[key].append(cwe)
    # 各年のCWEをリストとして取得
    all_cwe_lists = [eval(cwe_info) for cwe_info in sum(lists_dict.values(), [])]
    # 全てのCWEを取得
    all_cwes = list(set(cwe for cwe_list in all_cwe_lists for cwe in cwe_list))
    # 各年ごとにCWEのカウントを辞書に格納
    cwe_counts = defaultdict(list)
    for i, year_list in enumerate(lists_dict.values(), start=2020):
        cwe_count = defaultdict(int)

        # 各年のCWE情報をリストとして取得
        cwe_lists = [eval(cwe_info) for cwe_info in year_list]
        
        # リスト内の各CWEをカウント
        for cwe_list in cwe_lists:
            for cwe in cwe_list:
                cwe_count[cwe] += 1
        
        # 各CWEのカウントを年代ごとのリストに格納
        for cwe in all_cwes:
            cwe_counts[cwe].append(cwe_count[cwe])
    
    # 各リストを足し合わせた結果を格納するリストを初期化
    sum_list = []
    # 各キーごとにリストの要素を足し合わせて新しいリストを作成
    for key, value in cwe_counts.items():
        total_list = [sum(x) for x in zip(sum_list, value)]
        sum_list = total_list

    sorted_dict1 = dict(sorted(cwe_counts.items(), key=lambda item: sum(item[1]), reverse=True))
    keys_list = list(sorted_dict1.keys())

    #各cweの個数を年別ごとでカウント
    for i in keys_list:
        for j in range(1, len(jvn_list) + 1):
            yearlist_dict[f'yearlist{j}'].append(cwe_counts[str(i)][j - 1])
    a = len(all_cwes)
    alllist = [yearlist_dict[f'yearlist{i}'] for i in range(1, len(jvn_list) + 1)]

    #データラベルを作成
    for i in range(1,a+1):
        ri = f'データ{i}'
        datalist.append(ri)
    
    # カウント結果をCSVファイルに出力
    with open('1.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # ヘッダー行
        header = [''] + keys_list
        writer.writerow(header)
        writer.writerow([''] + datalist)

        for year, counts in zip(range(2021, 2024), alllist):
            writer.writerow([f'{year}'] + counts)
    csv_files = [f for f in os.listdir(DEMO_DIR) if f.endswith('.csv')]
    files = csv_files[0]
    title = 'CWE別脆弱性報告数推移'
    titles  = {'0': title}
    filess = []
    filess.append(files)
    i = 0

    # ファイルからデータを抜き出して処理→javascriptにデータを渡す
    indexList = {}
    dataList = {}
    data = []
    i = 0

    for file in filess:
        key = titles[str(i)]
        
        df, dateDf = csvToDf(file)
        os.remove(file)
        if i == 0:
            for j in df.columns:
                data.append(j)
        indexNest = {}

        for column in dateDf.columns:
            indexNest[column] = dfToList(dateDf[column])
        indexList[key] = indexNest
        dataNest = {}

        for column in df.columns:
            dataNest[column] = dfToList(df[column])
        dataList[key] = dataNest
        i += 1

        sum_dict = {}
        for key, value in dataList[title].items():
            total = sum(map(int, value))
            sum_dict[key] = total
    return render_template('cwe_graph.html', data=data, name=titles, dataList=dataList, 
                           indexList=indexList, vendor=vendor, ivendor=yearlist_dict['yearlist3'])

@cwe_graph.route('/select', methods=['POST'])
def select():
    data = request.json
    returnData = {}

    l = data['length'] - 2
    indexList = data[str(l)]
    dataList = data[str(l+1)]
    d1 = {}
    for key in dataList:
        i = 0
        itemList = []
        d2 = {}
        for i in range(l):
            item = data[str(i)]
            itemList.append(item)
            d2[item] = dataList[key][item]
        d1[key] = d2

    returnData['data'] = d1

    returnData['itemList'] = itemList
    dateFlag = 0
    if dateFlag:
        i = {}
        for key in indexList:
            i[key] = indexList[key]['ナンバー [-]']
        returnData['index'] = i
    else:
        i = {}
        for key in indexList:
            i[key] = indexList[key]['年月 [s]']
        returnData['index'] = i

    returnData = json.dumps(returnData, ensure_ascii=False)
    return returnData