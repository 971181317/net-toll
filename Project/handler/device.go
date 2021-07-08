package handler

import (
	"Project/service"
	"fmt"
	"github.com/google/gopacket/pcap"
	"os"
)

// GetDeviceNameHandel 获取设备并打印
func GetDeviceNameHandel() {
	devices := GetDeviceArrHandel()
	service.GetDeviceService(devices)
}

func GetDeviceArrHandel() []pcap.Interface {
	// 寻找所有的设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("寻找设备出错")
		os.Exit(1)
	}
	return devices
}
