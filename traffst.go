package main

import (
    "fmt"
    "flag"
    "os"
    "strconv"
    "sort"
    "bytes"
    "bufio"
    "net/http"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)


var (
    device  = flag.String("i", "eth0", "interface")
    count   = flag.Int("c", 1000, "count")
    snaplen = flag.Int("s", 65535, "snaplen")
    debug   = flag.Bool("d", false, "debug")
    help    = flag.Bool("h", false, "help")
)

type sortedMap struct {
    m map[string]int
    s []string
}

func (sm *sortedMap) Len() int {
    return len(sm.m)
}

func (sm *sortedMap) Less(i, j int) bool {
    return sm.m[sm.s[i]] > sm.m[sm.s[j]]
}

func (sm *sortedMap) Swap(i, j int) {
    sm.s[i], sm.s[j] = sm.s[j], sm.s[i]
}

func sortedKeys(m map[string]int) []string {
    sm := new(sortedMap)
    sm.m = m
    sm.s = make([]string, len(m))
    i := 0
    for key, _ := range m {
        sm.s[i] = key
        i++
    }
    sort.Sort(sm)
    return sm.s
}

func printStatistic(m map[string]int, name string, count int) {
    fmt.Printf("STATISTIC %s:\n", name)
    i := 0

    for _, res := range sortedKeys(m) {
        if i > count {
            break
        }
        fmt.Printf("%s => %d\n", res, m[res])
        i++
    }
    fmt.Printf("\n")
}


func main() {
    expr := ""

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "usage: %s [ -i interface ] [ -s snaplen ] [ -c count ] [ -d enable debug ] [ -h show usage] [ expression ] \n", os.Args[0])
        os.Exit(1)
    }

    flag.Parse()

    if len(flag.Args()) > 0 {
        expr = flag.Arg(0)
    }

    if *help {
        flag.Usage()
    }

    packetsCount := *count
    statisticIP := make(map[string]int)
    statisticTTL := make(map[string]int)
    statisticTCP := make(map[string]int)
    statisticHost := make(map[string]int)

    handle, err := pcap.OpenLive(*device, int32(*snaplen), true, pcap.BlockForever)
    if err != nil {
        panic(err)
    }

    if expr != "" {
        if err := handle.SetBPFFilter(expr); err != nil {
            fmt.Println(err)
        }
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    for packet := range packetSource.Packets() {
        if packetsCount <= 0 {
            break
        }

        packetsCount--

        if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
            ip, _ := ipLayer.(*layers.IPv4)
            if *debug {
                fmt.Printf("IP: src ip %s, dst ip %s, ttl %d\n", ip.SrcIP, ip.DstIP, ip.TTL)
            }
            statisticIP[ip.SrcIP.String()] += 1
            statisticIP[ip.DstIP.String()] += 1
            statisticTTL[strconv.Itoa(int(ip.TTL))] += 1
        }

        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
            tcp, _ := tcpLayer.(*layers.TCP)
            if *debug {
                fmt.Printf("TCP: src port %d, dst port %d\n", tcp.SrcPort, tcp.DstPort)
            }
            statisticTCP[tcp.SrcPort.String()] += 1
            statisticTCP[tcp.DstPort.String()] += 1

            if tcp.DstPort == 80 || tcp.DstPort == 443 {
                if app := packet.ApplicationLayer(); app != nil {
                    data := app.Payload()
                    reader := bytes.NewReader(data)
                    req, err := http.ReadRequest(bufio.NewReader(reader))

                    if err == nil {
                        statisticHost[req.Host] += 1
                    }
                }
            }
        }
    }

    printStatistic(statisticIP, "IP", 8)
    printStatistic(statisticTTL, "TTL", 8)
    printStatistic(statisticTCP, "TCP", 8)
    printStatistic(statisticHost, "Host", 10)

}
