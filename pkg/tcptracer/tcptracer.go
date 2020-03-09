package tcptracer

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
    //"path/filepath"
    //"runtime"
    "unsafe"
    bpf "github.com/iovisor/gobpf/bcc"
)

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

type TcpIpv4Event struct {
    TSns        uint64 // Current TimeStamp in nanoseconds
    TcpType     uint32
    Pid         uint32
    Comm        [16]byte // TASK_COMM_LEN=16
    IpVer       uint8
    Padding     [3]byte
    Saddr       uint32
    Daddr       uint32
    Sport       uint16
    Dport       uint16
    Netns       uint32
}

func TcpIpv4EventToString(event TcpIpv4Event) string {
    var logString string
    logString = fmt.Sprintf("%-8s %-6d %-11s IPv%-2d %-15s %-15s %-5d %-5d %-11d",
                            TcpTypeIntToString(event.TcpType),
                            event.Pid,
                            C.GoString( ((*C.char)(unsafe.Pointer(&event.Comm))) ),
                            event.IpVer,
                            IpIntToByte(event.Saddr),
                            IpIntToByte(event.Daddr),
                            event.Sport,
                            event.Dport,
                            event.Netns)

/*    fmt.Printf("%-8s %-6s %-11s %-5s %-15s %-15s %-5s %-5s %-11s\n",
                "TCPTYPE",
                "PID",
                "COMM",
                "IP",
                "SADDR",
                "DADDR",
                "SPORT",
                "DPORT",
                "NETNS")
*/
    fmt.Printf("%-8s %-6d %-11s IPv%-2d %-15s %-15s %-5d %-5d %-11d\n", 
                TcpTypeIntToString(event.TcpType),
                event.Pid,
                C.GoString( ((*C.char)(unsafe.Pointer(&event.Comm))) ),
                event.IpVer,
                IpIntToByte(event.Saddr),
                IpIntToByte(event.Daddr),
                event.Sport,
                event.Dport,
                event.Netns)
    return logString
}

var IsTracerDoneSig = make(chan bool, 1)
var IsTracerStopped bool = true
var IsTracerReady bool = false

func Start( logchannel chan TcpIpv4Event ) {
/*    _, b, _, _ := runtime.Caller(0)
    basePath   := filepath.Dir(b)
    newPath := filepath.Join(basePath, "tcptracer.bt")

    sourceByte, err := ioutil.ReadFile(newPath)
*/
    sourceByte, err := ioutil.ReadFile("tcptracer.bt")
    if err != nil {
        log.Fatal(err)
    }
    source := string(sourceByte)
    m := bpf.NewModule(source, []string{})
    defer m.Close()

    kprobe, err := m.LoadKprobe("trace_connect_v4_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_v4_connect", kprobe, 0)
    kprobe, err = m.LoadKprobe("trace_connect_v4_return")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_return: %s\n", err)
        os.Exit(1)
    }
    m.AttachKretprobe("tcp_v4_connect", kprobe, 0)
    kprobe, err = m.LoadKprobe("trace_tcp_set_state_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_tcp_set_state_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_set_state", kprobe, 0)
    kprobe, err = m.LoadKprobe("trace_close_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_close_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_close", kprobe, 0)
    kprobe, err = m.LoadKprobe("trace_accept_return")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_close_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKretprobe("inet_csk_accept", kprobe, 0)

    table := bpf.NewTable(m.TableId("tcp_ipv4_event"), m)

    channel := make(chan []byte)

    perfMap, err := bpf.InitPerfMap(table, channel)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
        os.Exit(1)
    }

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    fmt.Println("[lib] Tcp Tracer is Ready")
    fmt.Printf("%-8s %-6s %-11s %-5s %-15s %-15s %-5s %-5s %-11s\n",
                "TCPTYPE",
                "PID",
                "COMM",
                "IP",
                "SADDR",
                "DADDR",
                "SPORT",
                "DPORT",
                "NETNS")
    go func() {
        var event TcpIpv4Event
        for {
            data := <-channel
            err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
            if err != nil {
                fmt.Printf("failed to decode received data: %s\n", err)
                continue
            }
            //fmt.Printf( TcpIpv4EventToString(event) )
            logchannel <- event
            //logchannel <- tcpIpv4EventToString(event)
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
