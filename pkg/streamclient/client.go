package streamclient

import (
	"context"
	"google.golang.org/grpc"
	pb "github.com/orzohmygodorz/x-tracer/api"
	"github.com/orzohmygodorz/x-tracer/pkg/tcptracer"
	//"github.com/mJace/x-tracer/pkg/tcpconnlat"
	//"time"
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

	client := pb.NewSentLogClient(connect)
    /**/
    for i := range pidList {
        for j:= range pidList[i] {
            log.Printf(pidList[i][j])
        }
    }
    logchannel := make(chan tcptracer.TcpIpv4Event, 1)
    go tcptracer.Start(logchannel)
    //var event tcptracer.TcpIpv4Event
    /*go func() {
        for n := 0; n<10; n++ {
            err = c.startLogStream(client, &pb.Log{
                Pid:                  3422,
                ProbeName:            "net",
                Log:                  <-logchannel,
                TimeStamp:            "local current time",
            })
        }
    }()*/
    /**/
    for i:=0; i<1000; i++ {
        event := <-logchannel
        for j:=range pidList {
            for k:= range pidList[j] {
                //log.Println("  %s  %s", strconv.FormatUint(uint64(event.Pid), 10), pidList[j][k])
                if strconv.FormatUint(uint64(event.Pid), 10) == pidList[j][k] {
                    err = c.startLogStream(client, &pb.Log{
                        Pid:                  3422,
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
