from flask import Blueprint, render_template, request
import requests, re

import plotly.express as px
import pandas as pd

import plotly.graph_objects as go

make_graph = Blueprint('make_graph', __name__)

@make_graph.route('/graph', methods=['GET', 'POST'])
def graph():
  
  if request.method == 'POST':
    # フォームから年月の入力を取得
    start_year = request.form['start_year']
    start_month = request.form['start_month']
    end_year = request.form['end_year']
    end_month = request.form['end_month']

    url = 'https://jvndb.jvn.jp/myjvn'
    params = {'method':'getStatistics','feed':'hnd','theme':'sumCvss','type':'m','datePublicStartY':start_year,'datePublicStartM':start_month,'datePublicEndY':end_year,'datePublicEndM':end_month}
    response = requests.get(url,params=params)
    response_text = response.text

    pattern = '<mjstat:resData date="(\d{4}-\d\d)" cntAll="(\d+?)" cntC="(\d+?)" cntH="(\d+?)" cntM="(\d+?)" cntL="(\d+?)" cntN="(\d+?)"/>'
    # findall 
    results = re.findall(pattern, response_text)

    years = []
    total = []
    cvss_C = []
    cvss_H = []
    cvss_M = []
    cvss_L = []
    cvss_N = []
    for a, b, c, d, e, f, g in results:
        years.append(a)
        total.append(int(b))
        cvss_C.append(int(c))
        cvss_H.append(int(d))
        cvss_M.append(int(e))
        cvss_L.append(int(f))
        cvss_N.append(int(g))

    # データをDataFrameに変換
    data = {'年月': years, '脆弱性報告数': total}
    df = pd.DataFrame(data)

    # 折れ線グラフを作成
    fig = px.line(df, x='年月', y='脆弱性報告数', title=f'{start_year}年{start_month}月から{end_year}年{end_month}月までの脆弱性報告数', markers=True)

    fig.update_layout(
       title_font=dict(
          size=30
       ),
       xaxis=dict(titlefont=dict(size=20)),
       yaxis=dict(
          title='脆弱性報告数',
          titlefont=dict(
             size=20
          )
        )
       )

    # グラフをHTMLに変換
    graph_html = fig.to_html(full_html=False)
#ここまでが上のグラフ

#ここからが下のグラフ
    start_year_int = int(start_year)
    start_month_int = int(start_month)
    end_year_int = int(end_year)
    end_month_int = int(end_month) + 1
    # 指定した範囲内のデータ
    date_range = pd.date_range(start=f'{start_year_int}-{start_month_int:02d}', end=f'{end_year_int}-{end_month_int:02d}', freq='M')

    data = {
        'Date': date_range,
        '緊急:9.0-10.0': cvss_C[:len(date_range)],
        '重要:7.0-8.9': cvss_H[:len(date_range)],
        '警告:4.0-6.9': cvss_L[:len(date_range)],
        '注意0.1-3.9': cvss_M[:len(date_range)],
        'なし意:0': cvss_N[:len(date_range)]
    }
    df = pd.DataFrame(data)

    fig_line = go.Figure()
    # グラフの作成（4つのデータセットを同じグラフに表示）
    for column_name in ['緊急:9.0-10.0', '重要:7.0-8.9', '警告:4.0-6.9', '注意0.1-3.9', 'なし意:0']:
      fig_line.add_trace(
         go.Scatter(
            x=df['Date'],
            y=df[column_name],
            mode='lines+markers',
            name=column_name
         )
      )

    fig_line.update_layout(
      title=f'{start_year}年{start_month}月から{end_year}年{end_month}月までの脅威度別脆弱性報告数',
      title_font=dict(
         size=30
      ),
      xaxis=dict(title='年月',
                 titlefont=dict(size=20)),
      yaxis=dict(title='脆弱性報告数',
                 titlefont=dict(size=20)),
      hovermode='x'
    )

    graph_line = fig_line.to_html(full_html=False)
    #ここまでが下のグラフ

    return render_template('graph.html', graph_html=graph_html, graph_line=graph_line, 
                           start_year=start_year, start_month=start_month, end_year=end_year, end_month=end_month)

  return render_template('graph.html')