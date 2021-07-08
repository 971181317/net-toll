package handler

import (
	. "Project/service"
	. "Project/ttype"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
)

var (
	err    error
	handle *pcap.Handle
)

// PacketHandler 开始抓取
func PacketHandler(dataSource DataSource, ctx *ConfigCtx) {
	if dataSource == OfflineData {
		handle, err = pcap.OpenOffline(ctx.OfflineFilePath)
	} else if dataSource == RealTimeData {
		handle, err = pcap.OpenLive(ctx.DeviceName, ctx.SnapshotLen, ctx.Promiscuous, ctx.Timeout)
	}
	if err != nil {
		fmt.Printf("开启抓包错误 %s: %v", ctx.DeviceName, err)
		os.Exit(1)
	}
	//关闭handle
	defer handle.Close()

	//过滤
	if ctx.Filter != "" {
		err = handle.SetBPFFilter(ctx.Filter)
		if err != nil {
			fmt.Printf("过滤设置错误 %s: %v", ctx.DeviceName, err)
			os.Exit(1)
		}
	}

	//pcap文件指针
	var w *pcapgo.Writer = nil
	//json
	var jsonF *os.File = nil
	//html
	var htmlF *os.File = nil

	//创建json文件
	jsonF, err = os.Create(ctx.JsonFilePath) //创建文件
	if err != nil {
		fmt.Println("json文件创建失败")
	}

	//创建html文件
	htmlF, err = os.Create(ctx.HtmlFilePath) //创建文件
	if err != nil {
		fmt.Println("html文件创建失败")
	}

	// 打开输出pcap文件并写入头文件
	if dataSource == RealTimeData {
		f, _ := os.Create(ctx.RealTimeFilePath)
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(uint32(ctx.SnapshotLen), ctx.LinkType)
		defer f.Close()
	}

	// 开始解析包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	PacketService(packetSource, w, jsonF, htmlF, ctx)
}
