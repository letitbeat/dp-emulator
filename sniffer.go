package dp_emulator

import (
	"time"
	"log"
	"flag"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"net"
	"encoding/json"
	"os"
	"os/signal"
	"sync"
	"fmt"
	"net/http"
	"bytes"
	"io/ioutil"
)

var (
	//device       string        = "s1-eth1"
	snapshot_len int32         = 65535
	promiscuous  bool          = false
	timeout      time.Duration = -1 * time.Second

	flagInterfaces	=	flag.String("i", "", "Interface(s) to capture packets i.e eth0 or eth0, s1-eth1, s2-eth2")
	flagFilter 		= 	flag.String("f", "", "BPF filter string to user")

	wg = new(sync.WaitGroup)
)



func main() {

	flag.Parse()

	if *flagInterfaces == "" {
		log.Fatal("Missing interface(s) (-i eth0  or  eth0, s1-eth1).")
	}

	stop := make(chan struct{}, 2)

	//TODO: This should be removed when the call comes from another script...
	// Waiting for ^C
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for {
			select {
			case <-c:
				log.Println("'stop' signal received; stopping...")
				close(stop)
				return
			}
		}
	}()

	devicesToSniff := len(strings.Split(*flagInterfaces, ","))
	wg.Add(devicesToSniff)

	for _, device := range strings.Split(*flagInterfaces, ",") {
		go sniffDevice(device, stop)
	}

	wg.Wait()
}

type TransportType uint8

type PacketWrapper struct {
	Device 		string			`json:device`
	Type		TransportType	`json:type`
	SrcIP		net.IP			`json:src_ip`
	DstIP		net.IP			`json:dst_ip`
	SrcPort		string			`json:src_port`
	DstPort		string			`json:dst_port`
	Payload 	string			`json:payload`
	CapturedAt	time.Time		`json:captured_at`
}

const (
	TCP			TransportType = iota
	UDP
	ICMP
	)

func sniffDevice(d string, stop chan struct{}) {

	defer wg.Done()
	log.Printf("Sniffing Device: %s", d)
	// Open device
	var handle, err = pcap.OpenLive(d, snapshot_len, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if *flagFilter != "" {
		if err = handle.SetBPFFilter(*flagFilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}


	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	in := packetSource.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:

			if packet.Layer(layers.LayerTypeIPv4) == nil {
				continue
			}

			log.Printf("Device: %s", d)

			p := PacketWrapper{}
			p.Device = d
			p.CapturedAt = packet.Metadata().CaptureInfo.Timestamp//time.Now()

			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer != nil {
				ip, _ := ip4Layer.(*layers.IPv4)
				log.Printf("From %s to %s", ip.SrcIP, ip.DstIP)
				p.SrcIP = ip.SrcIP
				p.DstIP = ip.DstIP
			}

			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer != nil {
				p.Type = ICMP
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				log.Printf("DstPort: %s", tcp.DstPort)
				log.Printf("SrcPort: %s", tcp.SrcPort)

				p.DstPort = fmt.Sprintf("%s", tcp.DstPort)
				p.SrcPort = fmt.Sprintf("%s", tcp.SrcPort)
				p.Type = TCP
			}

			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				log.Printf("UDP DstPort: %s", udp.DstPort)
				log.Printf("UDP SrcPort: %s", udp.SrcPort)

				p.DstPort =	fmt.Sprintf("%s", udp.DstPort)
				p.SrcPort = fmt.Sprintf("%s", udp.SrcPort)
				p.Type = UDP
			}

			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				log.Printf("%+q", appLayer.Payload())
				p.Payload = string(appLayer.Payload())
			}

			sendPacket(p)
		}
	}

}

func sendPacket(p PacketWrapper) {
	url := "http://analyzer:5000/save"

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(p)

	req, err := http.NewRequest("POST", url,  b)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	log.Printf("response Status: %s", resp.Status)
	log.Printf("response Headers: %s", resp.Header)

	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("response Body: %s", string(body))
}
