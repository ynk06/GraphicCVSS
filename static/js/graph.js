// 画面遷移なしのおまじない
$(window).load(select());
$(window).load(outputHTML());

// グローバル変数
var dataList;
var indexList;
var list;
var listy2;
var graphData;
var titles = {};
var xtitle;
var ytitle;
var y2title;
let visibles = {}; //トレース線の表示/非表示用

//グラフのタイトルを取得
function getTitles() {
  var Get_Childnodes = window.document.getElementById('graphs').children; //グラフのIDから子要素のタイトルを取得
  var len = Get_Childnodes.length
  for (var i = 0; i < len; i++) {
    key = Get_Childnodes[i].firstElementChild.firstElementChild.name;
    titles[key] = Get_Childnodes[i].firstElementChild.firstElementChild.value;
  }
};
//グラフの軸タイトルや表示範囲などを取得
function getValues() {
  xtitle = $("#xtitle").val();
  ytitle = $("#ytitle").val();
};

//トレース線の表示/非表示を取得
function getVisibles(){
  //表示されているグラフの格納
  let displayGraph
  //#graphs要素内のすべてのdiv要素を取得、すべてのdiv要素が含まれる
  let displayGraphs = document.querySelectorAll('#graphs>div'); //#graphsの子要素からdivを抜き出す
  for(let i = 0; i < displayGraphs.length; i++){                //表示中のグラフを選択
    let displayState = displayGraphs[i].style.display;          //グラフのstyleからdisplayの値を取得
    if(displayState == ""){                                     //display""であれば（display"None"でなければ）
      displayGraph = displayGraphs[i];
    }
  }

  let traces = displayGraph.querySelectorAll('.groups>g');     //表示中のグラフからトレース線を抜き出す
  if(0 === Object.keys(visibles).length){    //visiblesが空かどうか調べる　→　https://qiita.com/te2u/items/b373914df693ddedf62e
    for(let i=0; i < graphData['itemList'].length; i++){  //空であればトレース線の表示/非表示を格納
      let titleSub = graphData['itemList'][i];            //graphData['itemList']からトレース線のタイトルを取得
      let opacityNow = parseFloat(traces[i].style.opacity);           //トレース線から透過率を取得
      if(opacityNow == 1){
        opacityNow = "True";
      }else{
        opacityNow = "legendonly";
      }
      visibles[titleSub] = opacityNow;       //トレース線のタイトルをkeyにして透過率を数値に変換して追加
    }
  }else{
    for(let i=0; i < graphData['itemList'].length; i++){  //空でなければvisiblesと現在のトレース線の透過率を比較して、変化があれば格納
      let titleSub = graphData['itemList'][i];            //graphData['itemList']からトレース線のタイトルを取得
      let opacityOld = visibles[titleSub];
      let opacityNow = parseFloat(traces[i].style.opacity);           //トレース線から透過率を取得
      if(opacityNow == 1){
        opacityNow = "True";
      }else{
        opacityNow = "legendonly";
      }
      if(opacityOld != opacityNow){                       //visiblesの値と比較
        visibles[titleSub] = opacityNow;                  //値が変化していればvisiblesの値を書き換える
      }
    }    
  }
}

// 画面遷移なしでpythonにデータを送る。itemFormで選択された項目のみのデータをpythonから取得。

function select() {
  $("#itemSubmit").click(function () {
    title = $("#title").val();
    xtitle = $("#xtitle").val();
    ytitle = $("#ytitle").val();
    var $checked = $("form#itemForm [name=item]:checked");
    list = $checked.map(function (index, el) {
      return $(this).val();
    });
    var json = list;
    json.push(indexList);
    json.push(dataList);
    json = JSON.stringify($(list));
    $.ajax({
      type: "POST",                 //pythonファイルにデータを送信
      url: "/select",               //python"main.py"の/selectを実行
      data: json,
      contentType: "application/json",
      success: function (data) {    //データの送信が成功すれば実行
        var data = JSON.parse(data);  //pythonからのデータをjavascript用に変換
        graphData = data;
        getTitles();
        makeGraph(graphData);
        visibles = {};                //visiblesを初期化
        getVisibles();                //visiblesにデータを格納
      }
    });
    return false;
  });
}

// 画面遷移なしでpythonにデータを送る。html作成。
function outputHTML() {
  $("#htmlSubmit").click(function () {
    var json = {
      listy2: listy2,
      graphData: graphData,
      titles: titles,
      xtitle: xtitle,
      ytitle: ytitle,
      visibles: visibles
    };
    json = JSON.stringify(json);
    return false;
  });
}

// 全選択スイッチ
$(function () {
  $("#all").on("click", function () {
    $("input[name='item']").prop("checked", this.checked);
  });

  $("input[name='item']").on("click", function () {
    if ($("#itemForm :checked").length == $("#itemForm :input").length) {
      $("#all").prop("checked", true);
    } else {
      $("#all").prop("checked", false);
    }
  });
});

// プルダウンの選択項目以外は非表示 発火はload時とchange時
$(function () {
  $("#select").on("change input", function () {
    var element = document.getElementById('select')
    id = element.value;
    var childElementCount = element.childElementCount;
    for (var i = 0; i < childElementCount; i++) {
      if (i != id) {
        document.getElementById(String(i)).style.display = "none";
      } else {
        document.getElementById(String(i)).style.display = "";
      }
    }
  }).change();
});

//第2y軸選択画面のhtmlを作成
function initCheckbox(d) {
  var chkboxstr = '<legend>第2y軸に追加するデータ系列</legend><div class="itemForm">';
};

// plotly描画
function makeGraph(data) {

  for (name in data["index"]) {
    var xv = data["index"][name];
    var yValues = data["data"][name];
    var plotData = [];
    var i = 0;
    for (key in yValues) {
      if (String(listy2).indexOf(data['itemList'][String(i)]) == -1) { //listy2に存在しなければ第1y軸にプロット
        var trace = {
          name: key,
          x: ['2021', '2022', '2023'],
          y: yValues[key],
          mode: "lines",
          type: "scatter",
          visible: visibles[key]
        };
      } else { //もし存在すれば第2y軸にプロットする
        var trace = {
          name: key,
          x: xv,
          y: yValues[key],
          mode: "lines",
          type: "scatter",
          yaxis: "y2",
          visible: visibles[key]
        };
      }
      plotData.push(trace);
      i += 1;
    }

    var layout = {
      title: titles[name],
      width: 780,
      height: 480,
      xaxis: {
        title: '年',
      },
      yaxis: {
        title: '脆弱性報告数',
      },
      legend: {
        x: 1.05
      }
    };

    Plotly.newPlot(name, plotData, layout);

  }
};
