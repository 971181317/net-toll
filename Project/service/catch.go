package service

import (
	"Project/ttype"
	"bytes"
	"encoding/json"
	"fmt"
	sj "github.com/bitly/go-simplejson"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"os"
	"strconv"
	"time"
)

var packetCount int32 = 0

// PacketService 解析数据包Handle，可提供写文件操作
func PacketService(packetSource *gopacket.PacketSource, w *pcapgo.Writer, jsonF *os.File, htmlF *os.File, ctx *ttype.ConfigCtx) {
	//创建json
	resJson := sj.New()
	//html写入头
	io.WriteString(htmlF, ttype.HtmlPre)

	for packet := range packetSource.Packets() {
		packetJson := sj.New()
		curTimeStr := time.Now().Format(time.UnixDate)

		if htmlF != nil {
			//将格式化的HTML写入html文件
			fmt.Fprintf(htmlF, "<div class=\"row text-center\"><h1>%s</h1></div>\n", curTimeStr)
		}

		analysisData(packet, htmlF, packetJson)
		packetJson.Set("time", curTimeStr)

		//有文件指针写文件
		if w != nil {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		packetCount++
		resJson.Set(fmt.Sprintf("result%d", packetCount), packetJson)
		if packetCount > ctx.PacketCount {
			break
		}

		//写html文件
		packetJsonStr, _ := packetJson.MarshalJSON()
		if htmlF != nil {
			//将格式化的HTML写入html文件
			fmt.Fprintf(htmlF, "<div class=\"row\"><pre class=\"block\">%s</pre></div>\n", packetJsonStr)
		}
	}

	//json字符串
	jsonStr, _ := resJson.MarshalJSON()

	//写json文件
	if jsonF != nil {
		//格式化的json
		var formatResJson bytes.Buffer
		err := json.Indent(&formatResJson, []byte(jsonStr), "", "\t")
		if err != nil {
			fmt.Println("json格式化失败")
		}
		//将格式化的json写入文件
		io.WriteString(jsonF, formatResJson.String())
	}

	//html写入尾
	io.WriteString(htmlF, ttype.HtmlEnd)
}

// analysisData 分析数据
func analysisData(packet gopacket.Packet, htmlF *os.File, json *sj.Json) {
	layersJson := map[string]interface{}{}
	// 以太网协议
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetLayerJson := map[string]interface{}{}
		fmt.Println("以太网：")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("- 源 MAC: ", ethernetPacket.SrcMAC.String())
		fmt.Println("- 目标 MAC: ", ethernetPacket.DstMAC.String())
		fmt.Println("- 以太网类型: ", ethernetPacket.EthernetType)
		fmt.Println()

		ethernetLayerJson["SrcMAC"] = ethernetPacket.SrcMAC.String()
		ethernetLayerJson["DstMAC"] = ethernetPacket.DstMAC.String()
		ethernetLayerJson["EthernetType"] = ethernetPacket.EthernetType
		layersJson["ethernet"] = ethernetLayerJson

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">Ethernet</h2>")
		fmt.Fprintf(htmlF, "<p>源 MAC&nbsp;:&nbsp;&nbsp;%s<p>\n", ethernetPacket.SrcMAC.String())
		fmt.Fprintf(htmlF, "<p>目标 MAC&nbsp;:&nbsp;&nbsp; %s<p>\n", ethernetPacket.DstMAC.String())
		fmt.Fprintf(htmlF, "<p>以太网类型&nbsp;:&nbsp;&nbsp;%s<p>\n", ethernetPacket.EthernetType)
		fmt.Fprintln(htmlF, "</div></div>")
	}

	// ip协议
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipLayerJson := map[string]interface{}{}
		fmt.Println("ipv4：")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Println("-源ip：", ip.SrcIP.String())
		fmt.Println("-目标ip：", ip.DstIP.String())
		fmt.Println("-报头长度：", ip.IHL)
		fmt.Println("-服务类型：", ip.TOS)
		fmt.Println("-长度：", ip.Length)
		fmt.Println("-生存时间值：", ip.TTL)
		fmt.Println("-校验码：", ip.Checksum)

		ipLayerJson["SrcIP"] = ip.SrcIP.String()
		ipLayerJson["DstIP"] = ip.DstIP.String()
		ipLayerJson["IHL"] = ip.IHL
		ipLayerJson["TOS"] = ip.TOS
		ipLayerJson["Length"] = ip.Length
		ipLayerJson["TTL"] = ip.TTL
		ipLayerJson["Checksum"] = ip.Checksum
		layersJson["ip"] = ipLayerJson
		fmt.Println()

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">IP</h2>")
		fmt.Fprintf(htmlF, "<p>源ip&nbsp;:&nbsp;&nbsp;%s<p>\n", ip.SrcIP.String())
		fmt.Fprintf(htmlF, "<p>目标ip&nbsp;:&nbsp;&nbsp; %s<p>\n", ip.DstIP.String())
		fmt.Fprintf(htmlF, "<p>报头长度&nbsp;:&nbsp;&nbsp;%d<p>\n", ip.IHL)
		fmt.Fprintf(htmlF, "<p>服务类型&nbsp;:&nbsp;&nbsp;%d<p>\n", ip.TOS)
		fmt.Fprintf(htmlF, "<p>长度&nbsp;:&nbsp;&nbsp;%d<p>\n", ip.Length)
		fmt.Fprintf(htmlF, "<p>生存时间值&nbsp;:&nbsp;&nbsp;%d<p>\n", ip.TTL)
		fmt.Fprintf(htmlF, "<p>校验码&nbsp;:&nbsp;&nbsp;%d<p>\n", ip.Checksum)
		fmt.Fprintln(htmlF, "</div></div>")
	}

	// tcp协议
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcpLayerJson := map[string]interface{}{}
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Println("-源端口：", tcp.SrcPort)
		fmt.Println("-目标端口：", tcp.DstPort)
		fmt.Println("-序列号：", tcp.Seq)
		fmt.Println("-确认号：", tcp.Ack)
		fmt.Println("-窗口大小：", tcp.Window)
		fmt.Println("-校验码：", tcp.Checksum)
		fmt.Println("-tcp类型：")
		var tcpOptionsJsonArr []interface{}
		for i := 0; i < len(tcp.Options); i++ {
			_m := map[string]interface{}{}
			fmt.Printf("---type：%s, 长度：%d\n", tcp.Options[i].OptionType.String(), tcp.Options[i].OptionLength)
			_m["OptionType"] = tcp.Options[i].OptionType.String()
			_m["OptionLength"] = tcp.Options[i].OptionLength
			tcpOptionsJsonArr = append(tcpOptionsJsonArr, _m)
		}
		var tcpFlagJsonArr []string
		fmt.Println("-tcp flag：")
		if tcp.FIN {
			fmt.Println("---FIN")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "FIN")
		}
		if tcp.SYN {
			fmt.Println("---SYN")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "SYN")
		}
		if tcp.RST {
			fmt.Println("---RST")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "RST")
		}
		if tcp.PSH {
			fmt.Println("---PSH")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "PSH")
		}
		if tcp.ACK {
			fmt.Println("---ACK")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "ACK")
		}
		if tcp.URG {
			fmt.Println("---URG")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "URG")
		}
		if tcp.ECE {
			fmt.Println("---ECE")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "ECE")
		}
		if tcp.CWR {
			fmt.Println("---CWR")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "CWR")
		}
		if tcp.NS {
			fmt.Println("---NS")
			tcpFlagJsonArr = append(tcpFlagJsonArr, "NS")
		}

		tcpLayerJson["SrcPort"] = tcp.SrcPort.String()
		tcpLayerJson["DstPort"] = tcp.DstPort.String()
		tcpLayerJson["Seq"] = tcp.Seq
		tcpLayerJson["Ack"] = tcp.Ack
		tcpLayerJson["Window"] = tcp.Window
		tcpLayerJson["Checksum"] = tcp.Checksum
		tcpLayerJson["tcp_flag"] = tcpFlagJsonArr
		tcpLayerJson["option"] = tcpOptionsJsonArr
		layersJson["tcp"] = tcpLayerJson
		fmt.Println()

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">TCP</h2>")
		fmt.Fprintf(htmlF, "<p>源端口&nbsp;:&nbsp;&nbsp;%s<p>\n", tcp.SrcPort.String())
		fmt.Fprintf(htmlF, "<p>目标端口&nbsp;:&nbsp;&nbsp;%s<p>\n", tcp.DstPort.String())
		fmt.Fprintf(htmlF, "<p>序列号&nbsp;:&nbsp;&nbsp;%d<p>\n", tcp.Seq)
		fmt.Fprintf(htmlF, "<p>确认号&nbsp;:&nbsp;&nbsp;%d<p>\n", tcp.Ack)
		fmt.Fprintf(htmlF, "<p>窗口大小&nbsp;:&nbsp;&nbsp;%d<p>\n", tcp.Window)
		fmt.Fprintf(htmlF, "<p>校验码&nbsp;:&nbsp;&nbsp;%d<p>\n", tcp.Checksum)
		fmt.Fprintln(htmlF, "<p>tcp类型&nbsp;:&nbsp;&nbsp;", tcpFlagJsonArr, "<p>")
		for idx, opts := range tcpOptionsJsonArr {
			if idx == 0 {
				fmt.Fprintf(htmlF, "<p>tcp flag&nbsp;:&nbsp;&nbsp;%d<p>\n", tcp.Checksum)
			}
			fmt.Fprintf(htmlF, "<p>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s&nbsp;:&nbsp;&nbsp;%d<p>\n",
				opts.(map[string]interface{})["OptionType"],
				opts.(map[string]interface{})["OptionLength"])
		}
		fmt.Fprintln(htmlF, "</div></div>")
	}

	// udp
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpLayerJson := map[string]interface{}{}
		fmt.Println("udp：")
		udp, _ := udpLayer.(*layers.UDP)

		fmt.Println("-源端口：", udp.SrcPort.String())
		fmt.Println("-目标端口：", udp.DstPort.String())
		fmt.Println("-校验码：", udp.Checksum)

		udpLayerJson["SrcPort"] = udp.SrcPort.String()
		udpLayerJson["DstPort"] = udp.DstPort.String()
		udpLayerJson["Checksum"] = udp.Checksum
		layersJson["udp"] = udpLayerJson
		fmt.Println()

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">UDP</h2>")
		fmt.Fprintf(htmlF, "<p>源端口&nbsp;:&nbsp;&nbsp;%s<p>\n", udp.SrcPort.String())
		fmt.Fprintf(htmlF, "<p>目标端口&nbsp;:&nbsp;&nbsp;%s<p>\n", udp.DstPort.String())
		fmt.Fprintf(htmlF, "<p>校验码&nbsp;:&nbsp;&nbsp;%d<p>\n", udp.Checksum)
		fmt.Fprintln(htmlF, "</div></div>")
	}

	// dns
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dnsLayerJson := map[string]interface{}{}
		fmt.Println("dns：")
		dns, _ := dnsLayer.(*layers.DNS)

		fmt.Println("-应答码：", dns.ResponseCode.String())
		fmt.Println("-是否期望递归：", dns.RD)
		fmt.Println("-是否支持递归：", dns.RA)
		fmt.Println("-截断：", dns.TC)
		fmt.Println("-问题记录数：", dns.QDCount)
		fmt.Println("-回答记录数：", dns.ANCount)
		fmt.Println("-授权记录数：", dns.NSCount)
		fmt.Println("-附加记录数：", dns.ARCount)

		dnsLayerJson["ResponseCode"] = dns.ResponseCode.String()
		dnsLayerJson["RD"] = dns.RD
		dnsLayerJson["RA"] = dns.RA
		dnsLayerJson["TC"] = dns.TC
		dnsLayerJson["QDCount"] = dns.QDCount
		dnsLayerJson["ANCount"] = dns.ANCount
		dnsLayerJson["NSCount"] = dns.NSCount
		dnsLayerJson["ARCount"] = dns.ARCount
		layersJson["dns"] = dnsLayerJson
		fmt.Println()

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">DNS</h2>")
		fmt.Fprintf(htmlF, "<p>应答码&nbsp;:&nbsp;&nbsp;%s<p>\n", dns.ResponseCode.String())
		fmt.Fprintf(htmlF, "<p>是否期望递归&nbsp;:&nbsp;&nbsp; %s<p>\n", strconv.FormatBool(dns.RD))
		fmt.Fprintf(htmlF, "<p>是否支持递归&nbsp;:&nbsp;&nbsp;%s<p>\n", strconv.FormatBool(dns.TC))
		fmt.Fprintf(htmlF, "<p>截断&nbsp;:&nbsp;&nbsp;%s<p>\n", strconv.FormatBool(dns.RA))
		fmt.Fprintf(htmlF, "<p>问题记录数&nbsp;:&nbsp;&nbsp;%d<p>\n", dns.QDCount)
		fmt.Fprintf(htmlF, "<p>回答记录数&nbsp;:&nbsp;&nbsp; %d<p>\n", dns.ANCount)
		fmt.Fprintf(htmlF, "<p>授权记录数&nbsp;:&nbsp;&nbsp;%d<p>\n", dns.NSCount)
		fmt.Fprintf(htmlF, "<p>附加记录数&nbsp;:&nbsp;&nbsp;%d<p>\n", dns.ARCount)
		fmt.Fprintln(htmlF, "</div></div>")
	}

	//引用层解析报文
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("应用层报文：")
		payload := applicationLayer.Payload()

		fmt.Println(payload)

		//写详细数据到html
		fmt.Fprintln(htmlF, "<div class=\"row\"><div class=\"block\">")
		fmt.Fprintln(htmlF, "<h2 class=\"text-center\">Application</h2>")
		fmt.Fprintln(htmlF, "<p>应用层报文&nbsp;:&nbsp;&nbsp;", payload, "<p>")
		fmt.Fprintln(htmlF, "</div></div>")

		str := "["
		for _, p := range payload {
			str += strconv.Itoa(int(p)) + " "
		}
		str += "]"
		json.Set("applicationLayerPayLoad", str)
	}

	// 打印所有层
	fmt.Println("所有层:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	json.Set("layer", layersJson)
}
