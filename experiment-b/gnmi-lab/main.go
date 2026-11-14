// Disposable read-only gNMI server with mutual TLS for integration tests.
// Not vendor router firmware, and not a production GNMI endpoint.
package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net"
    "os"
    "time"

    pb "github.com/openconfig/gnmi/proto/gnmi"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/status"
)

type target struct{ pb.UnimplementedGNMIServer }

func (target) Capabilities(ctx context.Context, _ *pb.CapabilityRequest) (*pb.CapabilityResponse, error) {
    return &pb.CapabilityResponse{GNMIVersion:"0.8.0", SupportedEncodings: []pb.Encoding{pb.Encoding_JSON_IETF}},nil
}

func (target) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse,error) {
    if len(req.GetPath())!=1 {
        return nil,status.Error(codes.InvalidArgument,"one allowed interface-state path required")
    }
    p:=req.GetPath()[0]
    names:=[]string{"interfaces","interface","state"}
    if len(p.GetElem())!=len(names) {
        return nil,status.Error(codes.InvalidArgument,"unsupported path")
    }
    for i,e:=range p.GetElem() {
        if e.GetName()!=names[i] {
            return nil,status.Error(codes.InvalidArgument,"unsupported path")
        }
    }
    update:=&pb.Update{
        Path:p,
        Val:&pb.TypedValue{Value:&pb.TypedValue_JsonIetfVal{
            JsonIetfVal:[]byte(`{"interface":[{"name":"ethernet1","state":{"name":"ethernet1","oper-status":"UP"}}]}`),
        }},
    }
    return &pb.GetResponse{Notification:[]*pb.Notification{{
        Timestamp:time.Now().UnixNano(),
        Update:[]*pb.Update{update},
    }}},nil
}

func main() {
    cert,err:=tls.LoadX509KeyPair(os.Getenv("LAB_GNMI_SERVER_CERT"),os.Getenv("LAB_GNMI_SERVER_KEY"))
    if err!=nil {panic(err)}
    ca,err:=os.ReadFile(os.Getenv("LAB_GNMI_CA"))
    if err!=nil {panic(err)}
    pool:=x509.NewCertPool()
    if !pool.AppendCertsFromPEM(ca) {panic("invalid client CA")}
    tlsConfig:=&tls.Config{MinVersion:tls.VersionTLS12,
        Certificates:[]tls.Certificate{cert},ClientAuth:tls.RequireAndVerifyClientCert,
        ClientCAs:pool}
    server:=grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
    pb.RegisterGNMIServer(server,target{})
    listener,err:=net.Listen("tcp","127.0.0.1:57400")
    if err!=nil {panic(err)}
    fmt.Println("DISPOSABLE GNMI MTLS GET SERVER READY ON LOOPBACK")
    if err:=server.Serve(listener);err!=nil {panic(err)}
}
