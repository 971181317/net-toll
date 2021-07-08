package ttype

import (
	"context"
	"github.com/google/gopacket/layers"
	"time"
)

// DataSource 数据源
type DataSource uint8

const (
	OfflineData  DataSource = 1 //离线数据
	RealTimeData DataSource = 2 //实时数据
)

// ConfigCtx 配置
type ConfigCtx struct {
	context.Context
	DeviceName       string          `yaml:"DeviceName"`
	SnapshotLen      int32           `yaml:"SnapshotLen"` //捕获一个数据包的多少个字节
	Promiscuous      bool            `yaml:"Promiscuous"` //设置网卡是否工作在混杂模式
	Filter           string          `yaml:"Filter"`
	OfflineFilePath  string          `yaml:"OfflineFilePath"`
	LinkType         layers.LinkType `yaml:"LinkType"`
	PacketCount      int32           `yaml:"PacketCount"`
	TimeoutSecond    int64           `yaml:"TimeoutSecond"` //设置抓到包返回的超时
	Timeout          time.Duration
	RealTimeFilePath string
	JsonFilePath     string
	HtmlFilePath     string
	DataSource       DataSource
}

const HtmlPre = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
	<script type="text/javascript" src="../../lib/jquery-1.11.0.min.js"></script>
    <link href="../../lib/bootstrap.min.css" rel="stylesheet">
    <script type="text/javascript" src="../../lib/bootstrap.min.js"></script>
    <style>
        body {
            background: #1c1c1c;
        }

        .block {
            font-size: 18px;
            color: white;
            padding: 5px;
            margin: 5px;
            background: #2d2d2d;
            border: none;
        }

        .key {
            color: rgb(255,121,170);
            font-weight: bold;
        }

        .null {
            color: #f1592a;
            font-weight: bold;
        }

        .string {
            color: rgb(241,250,118);
            font-weight: bold;
        }

        .number {
            color: rgb(156,147,249);
            font-weight: bold;
        }

        .boolean {
            color: rgb(156,147,249);
            font-weight: bold;
        }
		
		h1 {
          color: white;
        }

        body::-webkit-scrollbar-track {
            -webkit-box-shadow: inset 0 0 6px rgba(0, 0, 0, 0.1);
            background-color: #3d3d3d;
            border-radius: 10px;
        }

        body::-webkit-scrollbar {
            width: 10px;
            background-color: #3d3d3d;
        }

        body::-webkit-scrollbar-thumb {
            border-radius: 10px;
            background-color: rgb(0, 204, 204);
        }

        .block::-webkit-scrollbar-track {
            -webkit-box-shadow: inset 0 0 6px rgba(0, 0, 0, 0.1);
            background-color: #3d3d3d;
            border-radius: 10px;
        }

        .block::-webkit-scrollbar {
            width: 10px;
            background-color: #3d3d3d;
        }

        .block::-webkit-scrollbar-thumb {
            border-radius: 10px;
            background-color: rgb(0, 204, 204);
        }

 		p {
            margin-left: 10px;
        }
    </style>
</head>
<body>
<div class="container">`

const HtmlEnd = `</div>
<script>
    function JsonFormat() {
        let json = $(this).text()
        json = JSON.stringify(JSON.parse(json), undefined, 2);
        json = json.replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>');
        let res = json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            var cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
        $(this).html(res)
    }

    $('pre').each(JsonFormat);
</script>
</body>
</html>`