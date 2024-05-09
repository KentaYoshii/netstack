# Netstack

* [Introduction](#introdction)
* [Usage](#usage)
* [Performance](#performance)
* [Design](#design)

## Introduction
Welcome to Netstack. This repository contains an implementation of RFC-compliant IP/TCP over UDP link layer in Golang. The supported features include
- IP
    - ARP 
    - ICMP
    - Traceroute
    - Ping
    - Dynamic Routing/Forwading
- TCP
    - Congestion Control (Tahoe/Reno)
    - Zero Window Probing
    - Retransmissions
    - Sending/Receiving Files
    - Silly Window Syndrome

## Usage
- In a terminal, go to the root of the project and run
```
$ make all
```
- This will generate two binaries `vhost` and `vrouter`.
- Next we generate lnx files. Under `./nets`, one can find various network topology. 
    - For instance, _linear-r1h2_ is a network with two `vhost`s connected with a `vrouter` in the middle. 
    - Using a utility script, create the lnx files as follows
```
$ util/vnet_generate nets/linear-r1h2.json lnx
```
- The above command will generate 3 lnx files using _linear-r1h2_ network topology under lnx directory.
- Then we can run the program as follows
```
$ util/vnet_run lnx
```
- This will start up a tmux session with provided lnx files. 
    - For example, if _linear-r1h2_ was used, it will spawn three terminals where two of them are running `vhost` programs, each with its own lnx file and one `vrouter`.
- Type in `help` to see all the supported commands for each binary type.
```
[Host]

> help
------- -----------
Command Description                                                                    
------- -----------                                                                         
echo    Command Test                                                                                    
info    About the host                                                                                        
exit    Terminate this program                                                                          
li      List interfaces                                                                                 
lr      List routes                                                                                     
ln      List available neighbors                                                                        
up      Enable an interface                                                                             
down    Disable an interface                                                                            
send    Send test packet                                                                                
tracert Traceroute to given ip                                                                         
ping    Ping the given ip                                                                               
a       Start listening and accepting on a port                                                         
c       Connect to a listening socket at addr port                                                      
s       Send to the socket                                                                              
r       Read from the socket                                                                            
cl      Close the socket
ls      List socket table
sf      Send a file to the socket
rf      Read a file from the socket

[Router]

> help
------- -----------
Command Description                                                                    
------- -----------                        
echo    Command Test  
info    About router       
exit    Terminate this program
li      List interfaces
lr      List routes    
ln      List available neighbors
up      Enable an interface
down    Disable an interface
send    Send test packet
tracert Traceroute to given ip
ping    Ping the given ip
lossy   Set the drop late of the router
```
## Performance
- To measure the performance of IP/TCP implementation, we provide four files under `data/`
    - small (26.35KB)
    - medium (318.74KB)
    - large (1.98MB)
    - huge (7.98MB)
- Using the `sf` command, we measure the throughput by sending the "huge" file.
    - Throughput is calculated by 
    ```
    throughput = file_sz / (end_time - start_time)
    ```
    - The statitstics are collected using 
        - Apple M1 Pro
        - 16GB RAM
### Results
| File name | Loss % | Congestion Control | Throughput 
| --- | --- | --- | --- |
| huge | 0% | N/A | **2.506s** |
| huge | 0% | Tahoe | **2.518s** |
| huge | 0% | Reno | **2.181s** |
| huge | 2% | N/A | **98.210s** |
| huge | 2% | Tahoe | **17.032s** |
| huge | 2% | Reno | **16.732s** |

### Throughput Graphs
- 2% drop rate without Congestion Control
![](./image/lossy_normal_throughput)
- 2% drop rate with Tahoe Congestion Control
![](./image/lossy_tahoe_throughput)
- 2% drop rate with Reno Congestion Control
![](./image/lossy_reno_throughput)
## Design 
### IP Stack
The IP Stack is defined as below
```Golang
type IPStack struct {

	// Logger
	Logger *slog.Logger

	// RIP enabled?
	RipEnabled bool
	// TEST ONLY
	LossRate float64

	// Maps

	// Map from Subnet IP address to InterfaceInfo Struct
	Subnets map[netip.Prefix]*link.Link
	// Map for protocol number to higher layer handler function
	ProtocolHandlerMap map[uint8]ProtocolHandler
	// Forwarding Table (map from Network Prefix to NextHop IP)
	ForwardingTable map[netip.Prefix]proto.NextHop
	// Interface name to Prefix Address
	NameToPrefix map[string]netip.Prefix

	// Channels

	// Channel through whicn interfaces send IP packets to network layer
	IpPacketChan chan *packet.Packet
	// ICMP chan which specializes in dealing with ICMP packet
	ICMPChan chan *packet.Packet
	// Channel through which new route entries are sent
	RouteChan chan proto.NextHop
	// Channels through which triggered updates are communicated to link layer
	TriggerChans []chan proto.NextHop
	// Channel through which Sockets communicate with IP stack
	SendChan chan *proto.TCPPacket
	// Channel for getting non-serious error messages
	errorChan chan string
	// Debugging
	InfoChan chan string

	// Concurrency
	ftMtx sync.Mutex
}
```
### Interface
Each Link interface is defined as below
```Golang
type Link struct {
	// IP Address of this link
	IPAddr netip.Addr
	// UDP Address of this link
	ListenAddr netip.AddrPort
	// ARP Table
	ARPTable map[netip.Addr]netip.AddrPort
	// Listening Conn of this interface
	ListenConn *net.UDPConn
	// Name of this interface
	InterfaceName string
	// Status
	IsUp bool
	// Subnet Prefix that it is connected to
	Subnet netip.Prefix

	// Chan
	ErrorChan chan string
	InfoChan  chan string
	ARPChan   chan ARPEntry

	// For ARP
	// - to simulate, we kinda need these
	BroadCastAddrs []netip.AddrPort
}
```
### TCP Stack
TCP Stack is defined as below
```Golang
type TCPStackT struct {
	// Struct that represents TCPStack

	// Counter used for clock-based ISN generation
	// (RFC 9293: 3.4.1)
	ISNCTR uint32
	// Next Available Socket ID
	NextSID int
	// Socket Id to Key into TCB for ease of access from REPL
	SIDToTableKey map[int]SocketTableKey
	// The Cannonical table
	SocketTable map[SocketTableKey]*TCB
	StMtx       sync.Mutex
	// Bounded Ports
	BoundPorts map[int]bool
	// Channel through which we communicate with the ipstack
	SendChan chan *TCPPacket
	// Reap Chan
	ReapChan chan int
	// Logger
	Logger *slog.Logger
}
```
### Socket API
Socket API are used to interact with the TCB from upper layer
```Golang
// VListen creates a new listening socket bound to the specified port
// After binding, the listening socket moves into LISTEN state
// Returns the listening socket or error
func VListen(port uint16) (*VTCPListener, error) {}

// VAccept waits for new TCP connections on the given listening socket
// BLOCK until new connection is established
// Returns the new normal socket represneting the connection or error
func (li *VTCPListener) VAccept(tcbChan chan *proto.TCB) {}

// Creates a new socket that connects to the specified virtual IP address and port
// Up to util.NUM_RETRANS number of retransmission attemps are made until aborting
// Returns the new normal socket representing the connection or error
func VConnect(laddr netip.Addr, raddr netip.Addr, rport uint16) (*VTCPConn, error) {}

// Reads data from the TCP socket. Data is read into "buf"
// BLOCK when there is no available data to read.
// Unless a failure or EOF occurs, this should return at least 1 byte
// Return number of bytes read into the buffer.
// The returned error is nil on success, io.EOF if other side of connection has finished
// or another error describing other failure cases.
func VRead(tcb *proto.TCB, buf []byte) (int, error) {}

// Writes data to the TCP socket. Data to write is in "data"
// BLOCK until all data are in the send buffer of the socket
// Returns the number of bytes written to the connection.
func VWrite(tcb *proto.TCB, data []byte) (int, error) {}

// Initiates the connection termination process for this socket
// All subsequent calls to VRead and VWrite on this socket should return an error
// VClose only initiates the close process, hence it is non-blocking.
// VClose does not delete sockets
func VClose(tcb *proto.TCB) error {}
```
### Socket 
Socket/TCB is defined as below
```Golang
type TCB struct {
	// Struct that represents Transmission Control Block (TCB)

	// Associated Socket Id
	SID int
	// TCB State
	State int

	// 4-tuple
	Laddr netip.Addr
	Lport uint16
	Raddr netip.Addr
	Rport uint16

	// Communication between IP Stack and TCP Stack
	ReceiveChan chan *TCPPacket
	SendChan    chan *TCPPacket

	// TIME_WAIT timer reset channel
	TimeReset chan bool
	// Signal the Reaper for TCB removeal
	// after entering CLOSED state
	ReapChan chan int
	// Update to ACK cond
	// - when you receive new ACK number
	ACKCond sync.Cond
	// Update to RQ cond
	// - when you receive new ACK number
	RQUpdateCond sync.Cond
	// Update the thread that sends out data in send buffer
	SBufDataCond sync.Cond
	// Update the thread that puts data into send buffer
	SBufPutCond sync.Cond
	// Update the thread that send buffre is empty
	// - when waiting to send out FIN packet
	SBufEmptyCond sync.Cond
	// Update the reader that there is data to read in receive buffer
	RBufDataCond sync.Cond

	// Circular Send Buffer
	SendBuffer *socket.CircularBuffer
	// Circular Receive Buffer
	RecvBuffer *socket.CircularBuffer
	// Early Arrivals Queue
	EarlyArrivals []*TCPPacket

	// Retransmission Queue
	RetransmissionQ []*RQSegment
	// Mutex for updating Retransmission Queue
	RQMu sync.Mutex
	// Ticker for Retransmitting oldest unACK'ed segment
	RQTicker *time.Ticker
	// Retransmission Timeout (in ms)
	RTO float64
	// True if RTO timer is running
	RTOStatus bool
	// Smooth Round Trip Time
	SRTT float64
	// True if updating RTO for the first time
	First bool

	// Initial Sequence Numbers
	ISS uint32
	IRS uint32

	// Connection State Variables

	// - Oldest un-ACK'ed sequence number
	SND_UNA uint32
	// - Next sequence number to send
	SND_NXT uint32
	// - Send Window
	SND_WND uint32
	// - Next sequence number we expect to receive
	RCV_NXT uint32
	// - Receive Window
	RCV_WND uint32

	// Last Byte Read in Receive Buffer
	LBR uint32
	// Last Byte Written in Send Buffer
	LBW uint32

	// True if Zero Window Probing
	ProbeStatus bool
	// Signal to stop Zero Window Probing
	ProbeStopSignal chan bool

	// Congestion Control

	// True if using Congestion Control
	CCEnabled bool
	// "Reno" or "Tahoe"
	CCAlgo string
	// Congestion Window
	// - Variable that limits the amount of data a TCP can send
	CWND uint16
	// Slow Start Threshold
	SSThresh uint16
	// Number of Bytes ACK'ed
	// - Use during Congestion Avoidance
	NumBytesACK uint16
	// Flag to see if we can increment CWND during CA
	CAIncrementFlag bool

	// Fast Retransmit

	// Duplicate ACK count
	DupACKCount int
}
```