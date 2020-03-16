package streamclient

import (
	"context"
	"google.golang.org/grpc"
	pb "github.com/orzohmygodorz/x-tracer/api"
	"github.com/orzohmygodorz/x-tracer/pkg/tcptracer"
	"github.com/orzohmygodorz/x-tracer/pkg/tcpconnlat"
	"time"
    "log"
    "strconv"
)

type StreamClient struct {
	port string
	ip string
}

func New(servicePort string, masterIp string) *StreamClient{
	return &StreamClient{
		servicePort,
		masterIp}
}


func (c *StreamClient) StartClient (pidList [][]string) {
	connect, err := grpc.Dial(c.ip+":"+c.port, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("grpc.Dial err: %v", err)
	}

	defer connect.Close()
    defer tcptracer.Stop()
    defer tcpconnlat.Stop()

    client := pb.NewSentLogClient(connect)

    logchannel := make(chan tcptracer.TcpIpv4Event, 1)
    go tcptracer.Start(logchannel)
    go func() {
        for i := 0; i<100; i++ {
            event := <-logchannel
            for j:=range pidList {
                for k:= range pidList[j] {
                    //log.Println("  %s  %s", strconv.FormatUint(uint64(event.Pid), 10), pidList[j][k])
                    if strconv.FormatUint(uint64(event.Pid), 10) == pidList[j][k] {
                        err = c.startLogStream(client, &pb.Log{
                            Pid:                  int64(event.Pid),
                            ProbeName:            "net",
                            Log:                  tcptracer.TcpIpv4EventToString(event),
                            TimeStamp:            "local current time",
                        })
                        if err!= nil {
                            log.Fatalf("startLogStream fail.err: %v", err)
                        }
                    }
                }
            }
        }
    }()

    tcpconnlatLogChannel := make(chan tcpconnlat.TcpIpv4Data, 1)
    go tcpconnlat.Start( tcpconnlatLogChannel )
    go func() {
        for i := 0; i<100; i++ {
            tcpconnlatEvent := <-tcpconnlatLogChannel
            for j:=range pidList {
                for k:= range pidList[j] {
                    if strconv.FormatUint(uint64(tcpconnlatEvent.Pid), 10) == pidList[j][k] {
                        err = c.startLogStream(client, &pb.Log{
                            Pid:                  int64(tcpconnlatEvent.Pid),
                            ProbeName:            "net",
                            Log:                  tcpconnlat.TcpIpv4DataToString(tcpconnlatEvent),
                            TimeStamp:            "local current time",
                        })
                        if err!= nil {
                            log.Fatalf("startLogStream fail.err: %v", err)
                        }
                    }
                }
            }
        }
    }()
    for i := 30; i>0; i--{
        //log.Printf("[main] Call tcptracer.Stop() in %d seconds\n", i)
        time.Sleep(time.Duration(1) * time.Second)
    }
}

func (c *StreamClient) startLogStream(client pb.SentLogClient, r *pb.Log) error {
	stream, err := client.RouteLog(context.Background())
	if err != nil {
		return err
	}

	/*for n := 0; n<1; n++ {
		err := stream.Send(r)
		if err != nil {
			return err
		}
	}*/
    err = stream.Send(r)
    if err != nil {
        return err
    }

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}

	log.Printf("Response: %v", resp.Res)
	return nil

}
