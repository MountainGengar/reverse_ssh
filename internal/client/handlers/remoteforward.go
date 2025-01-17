package handlers

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/NHAS/reverse_ssh/internal"
	"golang.org/x/crypto/ssh"
)

type remoteforward struct {
	Listener net.Listener
	User     *internal.User
}

var (
	currentRemoteForwardsLck sync.RWMutex
	currentRemoteForwards    = map[internal.RemoteForwardRequest]remoteforward{}
)

func GetServerRemoteForwards() (out []string) {
	currentRemoteForwardsLck.RLock()
	defer currentRemoteForwardsLck.RUnlock()

	for a, c := range currentRemoteForwards {
		if c.User == nil {
			out = append(out, a.String())
		}
	}

	return out
}

func StopRemoteForward(rf internal.RemoteForwardRequest) error {
	currentRemoteForwardsLck.Lock()
	defer currentRemoteForwardsLck.Unlock()

	if _, ok := currentRemoteForwards[rf]; !ok {
		return fmt.Errorf("Unable to find remote forward request")
	}

	currentRemoteForwards[rf].Listener.Close()
	delete(currentRemoteForwards, rf)

	log.Println("Stopped listening on: ", rf.BindAddr, rf.BindPort)

	return nil
}

func StartRemoteForward(user *internal.User, r *ssh.Request, sshConn ssh.Conn) {

	var rf internal.RemoteForwardRequest
	err := ssh.Unmarshal(r.Payload, &rf)
	if err != nil {
		r.Reply(false, []byte(fmt.Sprintf("Unable to open remote forward: %s", err.Error())))
		return
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", rf.BindAddr, rf.BindPort))
	if err != nil {
		r.Reply(false, []byte(fmt.Sprintf("Unable to open remote forward: %s", err.Error())))
		return
	}
	defer l.Close()

	defer StopRemoteForward(rf)

	if user != nil {
		user.Lock()
		user.SupportedRemoteForwards[rf] = true
		user.Unlock()
	}

	//https://datatracker.ietf.org/doc/html/rfc4254
	responseData := []byte{}
	if rf.BindPort == 0 {
		port := uint32(l.Addr().(*net.TCPAddr).Port)
		responseData = ssh.Marshal(port)
		rf.BindPort = port
	}
	r.Reply(true, responseData)

	log.Println("Started listening on: ", l.Addr())

	currentRemoteForwardsLck.Lock()

	currentRemoteForwards[rf] = remoteforward{
		Listener: l,
		User:     user,
	}
	currentRemoteForwardsLck.Unlock()

	for {

		proxyCon, err := l.Accept()
		if err != nil {
			return
		}
		go handleData(proxyCon, sshConn)
	}

}

func handleData(proxyCon net.Conn, sshConn ssh.Conn) error {

	log.Println("Accepted new connection: ", proxyCon.RemoteAddr())

	lHost, strPort, err := net.SplitHostPort(proxyCon.RemoteAddr().String())
	if err != nil {
		return err
	}

	lPort, err := strconv.Atoi(strPort)
	if err != nil {
		return err
	}

	rHost, strPort, err := net.SplitHostPort(proxyCon.LocalAddr().String())
	if err != nil {
		return err
	}

	rPort, err := strconv.Atoi(strPort)
	if err != nil {
		return err
	}

	drtMsg := internal.ChannelOpenDirectMsg{
		Laddr: lHost,
		Lport: uint32(lPort),

		Raddr: rHost,
		Rport: uint32(rPort),
	}

	b := ssh.Marshal(&drtMsg)

	destination, reqs, err := sshConn.OpenChannel("forwarded-tcpip", b)
	if err != nil {
		log.Println("Opening forwarded-tcpip channel to server failed: ", err)

		return err
	}
	defer destination.Close()

	go ssh.DiscardRequests(reqs)

	log.Println("Forwarded-tcpip channel request sent and accepted")

	go func() {
		defer destination.Close()
		defer proxyCon.Close()
		io.Copy(destination, proxyCon)

	}()

	defer proxyCon.Close()
	_, err = io.Copy(proxyCon, destination)

	return err
}
