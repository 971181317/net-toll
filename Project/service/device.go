package service

import (
	"fmt"
	"github.com/google/gopacket/pcap"
)

// GetDeviceService 处理数据信息，并打印
func GetDeviceService(devices []pcap.Interface) {
	// 打印信息
	for _, device := range devices {
		fmt.Println("\n名称: ", device.Name)
		fmt.Println("描述: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP 地址: ", address.IP)
			fmt.Println("- 子网掩码: ", address.Netmask)
		}
	}
}
