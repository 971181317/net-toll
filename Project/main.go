package main

import (
	. "Project/handler"
	. "Project/ttype"
	"fmt"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

var (
	confCtx = ConfigCtx{}
	err     error
)

func main() {
	fmt.Println(pcap.Version())
	InitConf()
	//读取控制台参数
	args := os.Args
	//处理无参数情况
	if len(args) == 1 {
		fmt.Print("-h 获取帮助")
	} else {
		switch args[1] {
		case "-h":
			fmt.Println("-dn 获取设备信息")
			fmt.Println("-catch 实时抓包，保存内容到filePath")
			fmt.Println("-offline 从filePath中获取解析离线数据")
			fmt.Println("-speed 监控实时网速")
		case "-dn":
			GetDeviceNameHandel()
		case "-catch":
			InitFile()
			PacketHandler(RealTimeData, &confCtx)
		//分析离线数据
		case "-offline":
			InitFile()
			PacketHandler(OfflineData, &confCtx)
		case "-speed":
			SpeedHandler(&confCtx)
		default:
			fmt.Print("错误参数, -h获取帮助")
		}
	}
}

func InitConf() {
	//解析配置文件
	conf, err := ioutil.ReadFile("conf.yaml")
	if err != nil {
		fmt.Print(err)
	}
	yaml.Unmarshal(conf, &confCtx)
	confCtx.Timeout = time.Duration(confCtx.TimeoutSecond) * time.Second
}

func InitFile() {
	dir := "offline_data/" + strconv.FormatInt(time.Now().Unix(), 10)
	err = os.Mkdir(dir, os.ModePerm)
	if err != nil {
		fmt.Println(dir+"文件夹创建失败：", err.Error())
	} else {
		fmt.Println(dir + "文件夹创建成功！")
	}
	filePath := fmt.Sprintf("%s/pocket data", dir)
	confCtx.RealTimeFilePath = filePath + ".pcap"
	confCtx.JsonFilePath = filePath + ".json"
	confCtx.HtmlFilePath = filePath + ".html"
}
