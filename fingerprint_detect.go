package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLens sync.Map
var GlobalMaxCSSMsgCount sync.Map

func DetectPostHandshakeRecordsLens(config *Config) {
	for sni := range config.ServerNames {
		for alpn := range 3 { // 0, 1, 2
			key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
			if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
				go func() {
					defer func() {
						val, _ := GlobalPostHandshakeRecordsLens.Load(key)
						if _, ok := val.(bool); ok {
							GlobalPostHandshakeRecordsLens.Store(key, []int{})
						}
					}()
					target, err := net.Dial("tcp", config.Dest)
					if err != nil {
						return
					}
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					detectConn := &RecordDetectConn{
						Conn: target,
						Key:  key,
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					uConn := utls.UClient(detectConn, &utls.Config{
						ServerName: sni, // needs new loopvar behaviour
						NextProtos: nextProtos,
					}, fingerprint)
					if err = uConn.Handshake(); err != nil {
						return
					}
					io.Copy(io.Discard, uConn)
				}()
				go func() {
					now := time.Now()
					target, err := net.Dial("tcp", config.Dest)
					rtt := time.Since(now)
					if err != nil {
						return
					}
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					conn := &CCSDetectConn{
						Conn: target,
						Key:  key,
						rtt:  rtt,
					}
					uConn := utls.UClient(conn, &utls.Config{
						ServerName: sni, // needs new loopvar behaviour
						NextProtos: nextProtos,
					}, fingerprint)
					if err = uConn.Handshake(); err != nil {
						return
					}
				}()
			}
		}
	}
}

type RecordDetectConn struct {
	net.Conn
	Key     string
	CcsSent bool
}

func (c *RecordDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *RecordDetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	var postHandshakeRecordsLens []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
			data = data[length:]
		} else {
			break
		}
	}
	GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
	return 0, io.EOF
}

var CCSMsg = []byte{0x14, 0x3, 0x3, 0x0, 0x1, 0x1}

type CCSDetectConn struct {
	net.Conn
	rtt time.Duration
	Key string
}

func (c *CCSDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		var i int
		// 32(idx 31) → max allowed (what's we need)
		// 33(idx 32) → trigger remote TLS Alert
		// 34(idx 33) → trigger remote TCP RST
		// 35(idx 34) → write err, pass to system
		for i = range 35 {
			if _, err = c.Conn.Write(CCSMsg); err != nil {
				break
			} else {
				time.Sleep(c.rtt * 2)
			}
		}
		GlobalMaxCSSMsgCount.Store(c.Key, i-2)
	}
	return c.Conn.Write(b)
}
