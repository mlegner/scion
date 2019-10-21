// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// "Multiple paths" QUIC/SCION implementation.
package mpsquic

import (
	"crypto/tls"

	"github.com/lucas-clemente/quic-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"net"
	"fmt"
)

const (
	defKeyPath = "gen-certs/tls.key"
	defPemPath = "gen-certs/tls.pem"
)

// A Listener of QUIC
type server struct {
	tlsConf *tls.Config
	config  *quic.Config

	conn net.PacketConn
}

var (
	BackupPacketConns []net.PacketConn
	BackupRemotes []*snet.Addr
	activePacketConn net.PacketConn
	qsessions []quic.Session
	// Don't verify the server's cert, as we are not using the TLS PKI.
	cliTlsCfg = &tls.Config{InsecureSkipVerify: true}
	srvTlsCfg = &tls.Config{}
)

func Init(keyPath, pemPath string) error {
	if keyPath == "" {
		keyPath = defKeyPath
	}
	if pemPath == "" {
		pemPath = defPemPath
	}
	cert, err := tls.LoadX509KeyPair(pemPath, keyPath)
	if err != nil {
		return common.NewBasicError("mpsquic: Unable to load TLS cert/key", err)
	}
	srvTlsCfg.Certificates = []tls.Certificate{cert}
	return nil
}

func DialSCION(network *snet.SCIONNetwork, laddr, raddr *snet.Addr,
	quicConfig *quic.Config) (quic.Session, error) {

	return DialSCIONWithBindSVC(network, laddr, raddr, nil, addr.SvcNone, quicConfig)
}

func DialMPSCION(network *snet.SCIONNetwork, laddr *snet.Addr, raddrs []*snet.Addr,
	quicConfig *quic.Config) (quic.Session, error) {

	return DialMPSCIONWithBindSVC(network, laddr, raddrs, nil, addr.SvcNone, quicConfig)
}

func DialSCIONWithBindSVC(network *snet.SCIONNetwork, laddr, raddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	return quic.Dial(sconn, raddr, "host:0", cliTlsCfg, quicConfig)
}

func DialMPSCIONWithBindSVC(network *snet.SCIONNetwork, laddr *snet.Addr, raddrs []*snet.Addr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Session, error) {

	fmt.Printf("len(raddrs): %v\n", len(raddrs))
	for i, raddr := range raddrs {
		// Open as many SCION connection as we have raddrs with a different path

		laddr.Host.L4 = addr.NewL4UDPInfo(laddr.Host.L4.Port() + 1)
		fmt.Printf("DialMPSCIONWithBindSVC: raddr[%d]: %v", i, raddr)
		//sconn, err := snet.DialSCIONWithBindSVC("udp4", laddr, raddr, nil, svc)


		// sListen
		//sconn, err := sListen(network, laddr, baddr, svc)
		if network == nil {
			network = snet.DefNetwork
		}
		sconn, err := network.ListenSCIONWithBindSVC("udp4", laddr, baddr, svc, 0)
		// sListen

		if err != nil {
			return nil, err
		}
		fmt.Println(sconn.LocalAddr().String())
		if i == 0 {
			activePacketConn = sconn
			continue
		}
		BackupPacketConns = append(BackupPacketConns, sconn)
		BackupRemotes = append(BackupRemotes, raddrs[i])
		fmt.Printf("BackupRemotes[i].Path: %v\n", BackupRemotes[i-1].Path)
	}
	fmt.Printf("len(backupPacketConns): %v\n", len(BackupPacketConns))
	// Use dummy hostname, as it's used for SNI, and we're not doing cert verification.
	qsession, err := quic.Dial(activePacketConn, raddrs[0], "host:0", cliTlsCfg, quicConfig)
	if err != nil {
		return nil, err
	}
	qsessions = append(qsessions, qsession)
	return qsessions[0], nil
}

func SwitchMPSCIONConn(currentQuicSession quic.Session) (quic.Session, error) {
	fmt.Println("SwitchMPSCIONConn: Started switch")
	for i, pconn := range BackupPacketConns {
		err := quic.SwitchPConn(&currentQuicSession, pconn)
		if err != nil {
			continue
		}
		pconn.WriteTo([]byte(""), BackupRemotes[i])
		return currentQuicSession, nil
	}
	return nil, common.NewBasicError("mpsquic: No fallback connection available.", nil)
}

func ListenSCION(network *snet.SCIONNetwork, laddr *snet.Addr,
	quicConfig *quic.Config) (quic.Listener, error) {

	return ListenSCIONWithBindSVC(network, laddr, nil, addr.SvcNone, quicConfig)
}

func ListenSCIONWithBindSVC(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC, quicConfig *quic.Config) (quic.Listener, error) {

	if len(srvTlsCfg.Certificates) == 0 {
		return nil, common.NewBasicError("mpsquic: No server TLS certificate configured", nil)
	}
	sconn, err := sListen(network, laddr, baddr, svc)
	if err != nil {
		return nil, err
	}
	qListener, err := quic.Listen(sconn, srvTlsCfg, quicConfig)
	return qListener, err
}

func sListen(network *snet.SCIONNetwork, laddr, baddr *snet.Addr,
	svc addr.HostSVC) (snet.Conn, error) {

	if network == nil {
		network = snet.DefNetwork
	}
	return network.ListenSCIONWithBindSVC("udp4", laddr, baddr, svc, 0)
}
