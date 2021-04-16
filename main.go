package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type configTerm struct {
	address [4]byte
	name    string
}
type Query struct {
	datagram   []byte
	len        int
	clientAddr *net.UDPAddr
}

type Response struct {
	datagram []byte
}

type Info struct {
	threadNum1 int
	threadNum2 int
	log        string
	start      time.Time
}

const ThreadNums = 5
const ChanSize = 1024
const datagramSize = 2048
const configFile = "config2.txt"
const severIP = "202.38.64.56:53"

var configList []configTerm
var localhostAddr *net.UDPAddr
var serverAddr *net.UDPAddr
var resolverAddr *net.UDPAddr
var clientConn *net.UDPConn
var serverConn *net.UDPConn
var IDToAddr map[uint]*net.UDPAddr
var IDToAddrMutex sync.Mutex
var IDToInfo map[uint]*Info
var IDToInfoMutex sync.Mutex

func checkError(err error) {
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func readConfig() {
	f, err := os.Open("config/" + configFile)
	checkError(err)
	b1 := make([]byte, 256)
	n, err := f.Read(b1)
	checkError(err)
	s := string(b1[:n])
	rules := strings.Split(s, "\r\n")
	for i := 0; i < len(rules); i++ {
		//skip blank lines
		if rules[i] == "" {
			continue
		}
		rule := strings.Split(rules[i], " ")
		addr := strings.Split(rule[0], ".")
		p := [4]byte{0, 0, 0, 0}
		for j := 0; j < 4; j++ {
			for i := 0; i < len(addr[j]); i++ {
				p[j] *= 10
				p[j] += addr[j][i] - '0'
			}
		}
		checkError(err)
		configList = append(configList, configTerm{p, rule[1]})
	}
}

func threadPool(size int, queryChan <-chan Query, respondChan chan<- Response, printChan chan<- string, sendChan chan<- Query, receiveChan <-chan Response) {
	for i := 0; i < size; i++ {
		go workThread1(i, queryChan, respondChan, printChan, sendChan)
	}
	for i := size; i < 2*size; i++ {
		go workThread2(i, respondChan, receiveChan, printChan)
	}
}

func workThread1(ID int, queryChan <-chan Query, respondChan chan<- Response, printChan chan<- string, sendChan chan<- Query) {
	for query := range queryChan {
		start := time.Now()
		query.datagram = query.datagram[:query.len]
		if query.clientAddr.IP.String() == "127.0.0.1" {
			//var a byte = 256
			//var transactionID = a * messageReceived[0] + messageReceived[1]
			//var questions = a * messageReceived[4] + messageReceived[5]
			var i int
			var info []byte
			for i = 13; query.datagram[i] != 0; i++ {
				if query.datagram[i] <= 32 {
					info = append(info, '.')
				} else {
					info = append(info, query.datagram[i])
				}
			}
			var queryName = string(info)
			var log string
			var a uint = 256
			//typ means query type
			var typ = uint(query.datagram[i+1])*a + uint(query.datagram[i+2])

			var find = -1
			for i = 0; i < len(configList); i++ {
				if configList[i].name == queryName {
					find = i
					break
				}
			}

			//A type, hit query
			var respond Response
			respond.datagram = query.datagram
			if find != -1 {
				//flags: if ip = 0.0.0.0, set Rcode = 3
				log = fmt.Sprintf("Thread %d handled query: %38s", ID, queryName)
				respond.datagram[2] = 0x81
				if configList[find].address == [4]byte{0, 0, 0, 0} || typ == 28 {
					respond.datagram[3] = 0x83
					log += fmt.Sprintf("%15s", "Intercept")
				} else {
					respond.datagram[3] = 0x80
					log += fmt.Sprintf("%15s", "Local Resolve")
				}

				//answer RR
				respond.datagram[6] = 0x00
				respond.datagram[7] = 0x01
				//Answer RRs
				//Name (relatively coordinate of name from start of DNS)
				respond.datagram = append(respond.datagram, 0xc0)
				respond.datagram = append(respond.datagram, 0x0c)
				//Type:A or AAAA
				respond.datagram = append(respond.datagram, 0x00)
				if typ == 1 {
					respond.datagram = append(respond.datagram, 0x01)
				} else {
					respond.datagram = append(respond.datagram, 0x1c)
				}
				//Class:IN
				respond.datagram = append(respond.datagram, 0x00)
				respond.datagram = append(respond.datagram, 0x01)
				//Time To Live: 24 hours
				respond.datagram = append(respond.datagram, 0x00)
				respond.datagram = append(respond.datagram, 0x01)
				respond.datagram = append(respond.datagram, 0x51)
				respond.datagram = append(respond.datagram, 0x80)
				//Data length: A->4 AAAA->16
				respond.datagram = append(respond.datagram, 0x00)
				if typ == 1 {
					respond.datagram = append(respond.datagram, 0x04)
				} else {
					respond.datagram = append(respond.datagram, 0x10)
				}

				//IP address
				if typ == 1 {
					respond.datagram = append(respond.datagram, configList[find].address[0])
					respond.datagram = append(respond.datagram, configList[find].address[1])
					respond.datagram = append(respond.datagram, configList[find].address[2])
					respond.datagram = append(respond.datagram, configList[find].address[3])
				} else {
					for i := 0; i < 16; i++ {
						respond.datagram = append(respond.datagram, 0x00)
					}
				}
				respondChan <- respond
				end := time.Now()
				gap := end.Sub(start)
				log += fmt.Sprintf("%15s", gap)
				printChan <- log
			} else {

				sendChan <- query
				log = fmt.Sprintf("%35s", queryName)
				var transactionID = uint(query.datagram[0])<<8 + uint(query.datagram[1])
				var info = new(Info)
				info.threadNum1 = ID
				info.log = log
				info.start = start
				IDToInfoMutex.Lock()
				IDToInfo[transactionID] = info
				IDToInfoMutex.Unlock()
			}
		}
	}
}

func workThread2(ID int, responseChan chan<- Response, receiveChan <-chan Response, printChan chan<- string) {
	for respond := range receiveChan {
		responseChan <- respond
		var transactionID = uint(respond.datagram[0])<<8 + uint(respond.datagram[1])
		IDToInfoMutex.Lock()
		info, ok := IDToInfo[transactionID]
		if ok {
			delete(IDToInfo, transactionID)
		}
		IDToInfoMutex.Unlock()
		if ok {
			end := time.Now()
			gap := end.Sub(info.start)
			info.threadNum2 = ID
			var log string
			log = fmt.Sprintf("Thread %d, %d handled query: ", info.threadNum1, info.threadNum2)
			info.log = log + info.log
			info.log += fmt.Sprintf("%15s", "Relay")
			info.log += fmt.Sprintf("%15s", gap)
			printChan <- info.log
		}
	}
}

func writeToClientThread(respondChan <-chan Response) {
	for response := range respondChan {
		var err error
		var transactionID = uint(response.datagram[0])<<8 + uint(response.datagram[1])

		IDToAddrMutex.Lock()
		destAddr, ok := IDToAddr[transactionID]
		if ok {
			delete(IDToAddr, transactionID)
		}
		IDToAddrMutex.Unlock()
		if ok {
			_, err = clientConn.WriteToUDP(response.datagram, destAddr)
			checkError(err)
		}
	}
}

func sendToServerThread(sendChan <-chan Query) {
	for sendQuery := range sendChan {
		var err error
		_, err = serverConn.Write(sendQuery.datagram)
		checkError(err)
	}
}

func readFromServerThread(responseChan chan<- Response) {
	for {
		var response Response
		response.datagram = make([]byte, datagramSize)
		n, err := serverConn.Read(response.datagram)
		checkError(err)
		response.datagram = response.datagram[:n]
		responseChan <- response
	}
}

func printThread(printChan <-chan string) {
	for info := range printChan {
		fmt.Println(info)
	}
}

// After initialization, we use main as readThread
func main() {
	readConfig()

	var err error
	localhostAddr, err = net.ResolveUDPAddr("udp", "127.0.0.1:53")
	checkError(err)
	clientConn, err = net.ListenUDP("udp", localhostAddr)
	checkError(err)
	defer clientConn.Close()

	serverAddr, err = net.ResolveUDPAddr("udp", severIP)
	checkError(err)
	resolverAddr, err = net.ResolveUDPAddr("udp", "211.86.152.235:3000")
	checkError(err)
	serverConn, err = net.DialUDP("udp", resolverAddr, serverAddr)
	checkError(err)
	defer serverConn.Close()

	IDToAddr = make(map[uint]*net.UDPAddr, 5)
	IDToInfo = make(map[uint]*Info, 5)

	queryChan := make(chan Query, ChanSize)
	respondChan := make(chan Response, ChanSize)
	sendChan := make(chan Query, ChanSize)
	printChan := make(chan string, ChanSize)
	receiveChan := make(chan Response, ThreadNums)

	threadPool(ThreadNums, queryChan, respondChan, printChan, sendChan, receiveChan)
	go writeToClientThread(respondChan)
	go sendToServerThread(sendChan)
	go readFromServerThread(receiveChan)
	go printThread(printChan)

	fmt.Println("Server opened.")

	for {
		var query Query
		query.datagram = make([]byte, datagramSize)
		checkError(err)

		query.len, query.clientAddr, err = clientConn.ReadFromUDP(query.datagram)
		checkError(err)

		var transactionID = uint(query.datagram[0])<<8 + uint(query.datagram[1])
		IDToAddrMutex.Lock()
		IDToAddr[transactionID] = query.clientAddr
		IDToAddrMutex.Unlock()

		queryChan <- query
	}
}
