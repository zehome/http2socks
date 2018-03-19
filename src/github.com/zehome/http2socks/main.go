package main

import "io"
import "os"
import "fmt"
import "net"
import "flag"
import "bufio"
import "encoding/binary"

const STATE_AUTH int = 0
const STATE_REQUEST int = 1
const STATE_DATA int = 2

type http2goconf struct {
	bind_host   string
	bind_port   int
	remote_host string
	remote_port int
}

func reload(config http2goconf) {
	fmt.Println("bind_host: %s bind_port: %d", config.bind_host, config.bind_port)
}

func main() {
	var config http2goconf
	flag.StringVar(&config.bind_host, "bind_host", "::1", "Host address to bind to")
	flag.IntVar(&config.bind_port, "bind_port", 1081, "Port to bind to")
	flag.Parse()

	fmt.Println("config: ", config)

	listen_conn, err := net.Listen("tcp", fmt.Sprintf("[%s]:%d", config.bind_host, config.bind_port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer listen_conn.Close()
	for {
		conn, err := listen_conn.Accept()
		if err != nil {
			fmt.Println("Error in accept:", err.Error())
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	defer conn.Close()
	state := STATE_AUTH
	for {
		switch state {
		case STATE_AUTH:
			version, err := reader.ReadByte()
			if version != 5 {
				fmt.Printf("Unacceptable version: %d\n", int(version))
				return
			}
			if err != nil {
				fmt.Println("read error:", err.Error())
				return
			}
			nmethods, err := reader.ReadByte()
			if err != nil {
				fmt.Println("read error:", err.Error())
				return
			}
			acceptable := false
			for i := 0; i < int(nmethods); i += 1 {
				method, err := reader.ReadByte()
				if err != nil {
					fmt.Println("read error:", err.Error())
					return
				}
				switch method {
				case 0: /* NO AUTHENTICATION REQUIRED */
					acceptable = true
				}
			}
			fmt.Printf("Version: %d acceptable methods: %t\n", version, acceptable)
			if !acceptable {
				writer.Write([]byte{5, 255})
				defer writer.Flush()
				return
			} else {
				_, err := writer.Write([]byte{5, 0})
				if err != nil {
					fmt.Println("write error:", err.Error())
					return
				}
				writer.Flush()
			}
			state = STATE_REQUEST
		case STATE_REQUEST:
			var ip net.IP
			fmt.Println("switched to state command")
			header := make([]byte, 3)
			if readlen, err := io.ReadAtLeast(reader, header, 3); err != nil {
				fmt.Println("read error:", err.Error())
				return
			} else {
				fmt.Printf("< %d bytes\n", readlen)
			}

			version := header[0]
			if version != 5 {
				fmt.Println("Unacceptable version: %d\n", version)
				return
			} else {
				fmt.Println("version:", version)
			}
			command := header[1]
			switch command {
			case 1: /* CONNECT */
				fmt.Print("connect to ")
			case 2: /* BIND */
				fmt.Print("bind ")
			case 3: /* UDP associate */
				fmt.Print("udp associate ")
			default:
				fmt.Printf("unknown command: %x\n", command)
				return
			}
			if addrtype, err := reader.ReadByte(); err != nil {
				fmt.Println("read error:", err.Error())
				return
			} else {
				switch addrtype {
				case 1: /* IPv4 */
					buf := make([]byte, 4)
					if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
						fmt.Println("read error: ", err.Error())
						return
					}
					ip = net.IPv4(buf[0], buf[1], buf[2], buf[3])
					fmt.Printf("%s", ip.String())
				case 3: /* Domain Name */
					stringlen, _ := reader.ReadByte()
					if err != nil {
						fmt.Println("read error: ", err.Error())
						return
					}
					buf := make([]byte, stringlen)
					if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
						fmt.Println("read error: ", err.Error())
						return
					}
					if ips, err := net.LookupIP(string(buf)); err != nil {
						fmt.Println("lookup error", err.Error())
						return
					} else {
						fmt.Printf("%s(%s)", buf, ips)
						for _, tmpip := range ips {
							if tmpip.To4() != nil {
								ip = tmpip
								break
							}
						}
					}
				case 4: /* IPv6 */
					buf := make([]byte, 16)
					if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
						fmt.Println("read error: ", err.Error())
						return
					}
					ip = net.IP(buf)
					fmt.Printf("to %s", ip)
				default:
					fmt.Println("unknown address type")
					return
				}
			}
			buf := make([]byte, 2)
			if _, err := io.ReadAtLeast(reader, buf, len(buf)); err != nil {
				fmt.Println("read error: ", err.Error())
				return
			}
			port := binary.BigEndian.Uint16(buf)
			fmt.Printf(":%d\n", port)
			if ip == nil {
				reply := []byte{5, 3, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port & 0xff)}
				writer.Write(reply)
				return
			}

			fmt.Println("command: ", command)
			if command == 1 {
				connhost := fmt.Sprintf("%s:%d", ip, port)
				destconn, err := net.Dial("tcp", connhost)
				if err != nil {
					fmt.Println("connection error:", err.Error())
					reply := []byte{5, 3, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port & 0xf)}
					writer.Write(reply)
					return
				}
				defer destconn.Close()
				laddr := destconn.LocalAddr().(*net.TCPAddr)
				reply := make([]byte, 4+4+2)
				reply[0] = 5
				reply[1] = 0
				reply[2] = 0
				reply[3] = 1
				copy(reply[4:], laddr.IP.To4())
				reply[8] = byte(port >> 8)
				reply[9] = byte(port & 0xff)
				fmt.Println("reply", reply)
				writer.Write(reply)
				writer.Flush()

				chans := make([]chan error, 2)
				go forward(destconn, conn, chans[0])
				go forward(conn, destconn, chans[1])
				select {
				case cerr, ok := <-chans[0]:
					if ok {
						fmt.Println("connection closed")
						return
					}
					if cerr != nil {
						fmt.Println("forward error:", cerr.Error())
					}
				case cerr, ok := <-chans[1]:
					if ok {
						fmt.Println("connection closed")
						return
					}
					if cerr != nil {
						fmt.Println("forward error:", cerr.Error())
					}
				}
				return
			}
			return
		}
	}
}

func forward(writer io.Writer, reader io.Reader, c chan error) {
	defer close(c)
	fmt.Println("forwarding..")
	written, err := io.Copy(writer, reader)
	fmt.Printf("EOF: written: %d bytes\n", written)
	c <- err
}
