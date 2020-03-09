package tcpconnlat

import (
    "C"
    "bytes"
    "encoding/binary"
    //"errors"
    "fmt"
    //"time"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/signal"
//    "path/filepath"
//    "runtime"
    "unsafe"
    bpf "github.com/iovisor/gobpf/bcc"
)

var start_ts uint64 = 0

func IpIntToByte(ip uint32) net.IP {
    result := make(net.IP, 4)
            result[0] = byte(ip)
            result[1] = byte(ip >> 8)
            result[2] = byte(ip >> 16)
            result[3] = byte(ip >> 24)
    return result
}

func TcpTypeIntToString(TcpType uint32) string {
    result := "unknown"
    if TcpType == 1 {
        result = "connect"
    } else if TcpType == 2 {
        result = "accept"
    } else if TcpType == 3 {
        result = "close"
    }
    return result
}

type tcpIpv4Data struct {
    TSus        uint64 // Current TimeStamp in nanoseconds
    Pid         uint32
    Saddr       uint32
    Daddr       uint32
    _           uint32
    Ip          uint64
    Dport       uint16
    Padding     [6]byte
    DeltaNs     uint64
    Comm        [16]byte // TASK_COMM_LEN=16
}

func tcpIpv4DataToString(event tcpIpv4Data) string {
    var logString string
    logString = fmt.Sprintf("%-9.3f %-6d  %-15s %-15s IPv%-2d %-5d %-8.2f %-11s",
                            float64(event.TSus - start_ts)/1000000,
                            event.Pid,
                            IpIntToByte(event.Saddr),
                            IpIntToByte(event.Daddr),
                            event.Ip,
                            event.Dport,
                            float64(event.DeltaNs)/1000,
                            C.GoString( ((*C.char)(unsafe.Pointer(&event.Comm))) ))
    return logString
}

var IsTracerDoneSig = make(chan bool, 1)

func Start(logchannel chan string) {
/*    _, b, _, _ := runtime.Caller(0)
    basePath   := filepath.Dir(b)
    newPath := filepath.Join(basePath, "tcpconnlat.bt")

    sourceByte, err := ioutil.ReadFile(newPath)
*/
    sourceByte, err := ioutil.ReadFile("tcpconnlat.bt")
    if err != nil {
        log.Fatal(err)
    }
    source := string(sourceByte)
    m := bpf.NewModule(source, []string{})
    defer m.Close()

    kprobe, err := m.LoadKprobe("trace_connect")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_v4_connect", kprobe, 0)
    kprobe, err = m.LoadKprobe("trace_tcp_rcv_state_process")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_return: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_rcv_state_process", kprobe, 0)
    table := bpf.NewTable(m.TableId("ipv4_data"), m)

    channel := make(chan []byte)

    perfMap, err := bpf.InitPerfMap(table, channel)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
        os.Exit(1)
    }

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    fmt.Println("[lib] Tcp Tracer is Ready")
    go func() {
        var event tcpIpv4Data
        for {
            data := <-channel
            err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
            if err != nil {
                fmt.Printf("failed to decode received data: %s\n", err)
                continue
            }
            if start_ts==0 {
                start_ts = event.TSus
            }
            fmt.Println( tcpIpv4DataToString(event) )
            logchannel <- tcpIpv4DataToString(event)
            start_ts = event.TSus
        }
    }()

    perfMap.Start()
    <-IsTracerDoneSig
    perfMap.Stop()
}

func Stop() {
    IsTracerDoneSig <- true
    fmt.Println("[lib] Tcp Tracer is Stopped")
}

