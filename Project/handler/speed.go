package handler

import (
	"Project/service"
	"Project/ttype"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
)

func SpeedHandler(ctx *ttype.ConfigCtx) {
	devices := GetDeviceArrHandel()

	// 根据网卡名称从所有网卡中取到精确的网卡
	var device pcap.Interface
	for _, d := range devices {
		if d.Name == ctx.DeviceName {
			device = d
		}
	}

	// 根据网卡的ipv4地址获取网卡的mac地址，用于后面判断数据包的方向
	macAddr, err := findMacAddrByIp(findDeviceIpv4(device))
	if err != nil {
		fmt.Printf("获取mac地址出错 %s: %v", ctx.DeviceName, err)
		os.Exit(1)
	}

	fmt.Printf("IP 地址: %s\n", findDeviceIpv4(device))
	fmt.Printf("MAC 地址: %s\n", macAddr)

	// 获取网卡handler，可用于读取或写入数据包
	handle, err = pcap.OpenLive(ctx.DeviceName, ctx.SnapshotLen, ctx.Promiscuous, ctx.Timeout)
	if err != nil {
		fmt.Printf("开启抓包错误 %s: %v", ctx.DeviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	service.SpeedService(packetSource, macAddr, ctx)
}

// 获取网卡的IPv4地址
func findDeviceIpv4(device pcap.Interface) string {
	for _, addr := range device.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	panic("硬件没有ipv4")
}

// 根据网卡的IPv4地址获取MAC地址
// 有此方法是因为gopacket内部未封装获取MAC地址的方法，所以这里通过找到IPv4地址相同的网卡来寻找MAC地址
func findMacAddrByIp(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(interfaces)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				if ip == a.IP.String() {
					return i.HardwareAddr.String(), nil
				}
			}
		}
	}
	return "", errors.New(fmt.Sprintf("寻找mac err: %s", ip))
}
