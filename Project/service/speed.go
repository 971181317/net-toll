package service

import (
	"Project/ttype"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"time"
)

var (
	downStreamDataSize = 0 // 单位时间内下行的总字节数
	upStreamDataSize   = 0 // 单位时间内上行的总字节数
)

func SpeedService(packetSource *gopacket.PacketSource, macAddr string, ctx *ttype.ConfigCtx) {
	// 开启子线程，每一秒计算一次该秒内的数据包大小平均值，并将下载、上传总量置零
	go monitor()

	// 开始抓包
	for packet := range packetSource.Packets() {
		// 只获取以太网帧
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernet := ethernetLayer.(*layers.Ethernet)
			// 如果封包的目的MAC是本机则表示是下行的数据包，否则为上行
			if ethernet.DstMAC.String() == macAddr {
				downStreamDataSize += len(packet.Data()) // 统计下行封包总大小
			} else {
				upStreamDataSize += len(packet.Data()) // 统计上行封包总大小
			}
		}
	}
}

// 每一秒计算一次该秒内的数据包大小平均值，并将下载、上传总量置零
func monitor() {
	for {
		fmt.Print(fmt.Sprintf("\rDown:%.2fkb/s \t Up:%.2fkb/s", float32(downStreamDataSize)/1024/1, float32(upStreamDataSize)/1024/1))
		downStreamDataSize = 0
		upStreamDataSize = 0
		time.Sleep(1 * time.Second)
	}
}
