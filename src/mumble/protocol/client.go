package protocol

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"time"

	"mumble/protocol/mumbleproto"

	"github.com/golang/protobuf/proto"
)

// A client connection
// TODO: Client validations should be going in this module, and tested individually, keep it dry and simple for testing
type Client struct {
	// Logging
	*log.Logger

	// TODO: What is a log forwarder? Can it be replaced and this module simplified by just using existing logging library that is community maintained? Lets focus on what makes this DIFFERENt isntead of remaking every wheel worse than the community maintained libraries
	logForwarder *LogForwarder

	// Connection-related
	tcpAddr    *net.TCPAddr
	udpAddr    *net.UDPAddr
	connection net.Conn
	reader     *bufio.Reader
	state      int
	server     *Server

	udpReceive chan []byte

	disconnected bool

	lastResync   int64
	crypt        CryptState
	codecs       []int32
	opus         bool
	udp          bool
	voiceTargets map[uint32]*VoiceTarget

	// Ping stats
	// TODO: Good candidate for a nested struct, it even has a name
	UdpPingAvg float32
	UdpPingVar float32
	UdpPackets uint32
	TcpPingAvg float32
	TcpPingVar float32
	TcpPackets uint32

	// If the client is a registered user on the server,
	// the user field will point to the registration record.
	user *User

	// The clientReady channel signals the client's reciever routine that
	// the client has been successfully authenticated and that it has been
	// sent the necessary information to be a participant on the server.
	// When this signal is received, the client has transitioned into the
	// 'ready' state.
	clientReady chan bool

	// Version
	// TODO: Good candidate for a nested struct, it even has a name
	Version    uint32
	ClientName string
	OSName     string
	OSVersion  string
	CryptoMode string

	// Personal
	// TODO: Good candidate for a nested struct, it even has a name
	Username        string
	session         uint32
	certHash        string
	Email           string
	tokens          []string
	Channel         *Channel
	SelfMute        bool
	SelfDeaf        bool
	Mute            bool
	Deaf            bool
	Suppress        bool
	PrioritySpeaker bool
	Recording       bool
	PluginContext   []byte
	PluginIdentity  string
}

// Debugf implements debug-level printing for Clients.
// TODO: Seems like this should be isolated into a debug/log module and not reimplemented in each and every datatype. Nicht so DRY
func (client *Client) Debugf(format string, v ...interface{}) {
	client.Printf(format, v...)
}

// Is the client a registered user?
// TODO: Doesn't seem like the appropriate way to do this check, we only check if the struct has the value set and not if the server has the user registered? Seems totally wrong and not actually checking what the fucntion name is implying
func (client *Client) IsRegistered() bool {
	return client.user != nil
}

// Does the client have a certificate?
// TODO: Should this not be a failure implemented as a validation and returning an error?
func (client *Client) HasCertificate() bool {
	return len(client.certificateHash) > 0
}

// Is the client the SuperUser?
func (client *Client) IsSuperUser() bool {
	// TODO: This is repated from earlier, so its definitely needed as a implmeneted as a validation function. Diese is nicht so dry
	if client.user == nil {
		return false
	}
	// TODO: Only 1 super user allowed using this method, doesn't seem that flexible, Maybe if we add an attribute or create a user DB, we can actually have roles =p
	return client.user.ID == 0

}

func (client *Client) ACLContext() *acl {
	return &client.Channel.ACL
}

func (client *Client) CertificateHash() string {
	return client.certificateHash
}

func (client *Client) Session() uint32 {
	return client.session
}

func (client *Client) Tokens() []string {
	return client.tokens
}

// Get the User ID of this client.
// Returns -1 if the client is not a registered user.
func (client *Client) UserID() int {
	// TODO: Third fucking time we did this check, come on, lets make validating functions and use them for consistent functionality, smaller code footprint and easier testing!
	if client.user == nil {
		// TODO: No, lets not plz
		return -1
	}
	// TODO: Seriously why are we returning it as an int? Just use a bool and only have uints32 so we dont convert 500 times
	return int(client.user.ID)
}

// Get the client's shown name.
func (client *Client) ShownName() string {
	// TODO: Why are we hardcoding the admin accounts names? Seems dirty and not flexible. Dont do this, just have the first user that registers be an admin and have it be a role so others can apply
	if client.IsSuperUser() {
		return "SuperUser"
	}
	if client.IsRegistered() {
		return client.user.Name
	}
	return client.Username
}

// Check whether the client's certificate is
// verified.
func (client *Client) IsVerified() bool {
	tlsconn := client.conn.(*tls.Conn)
	state := tlsconn.ConnectionState()
	return len(state.VerifiedChains) > 0
}

// Log a panic and disconnect the client.
func (client *Client) Panic(v ...interface{}) {
	client.Print(v)
	client.Disconnect()
}

// Log a formatted panic and disconnect the client.
func (client *Client) Panicf(format string, v ...interface{}) {
	client.Printf(format, v...)
	client.Disconnect()
}

// Internal disconnect function
func (client *Client) disconnect(kicked bool) {
	if !client.disconnected {
		client.disconnected = true
		client.server.RemoveClient(client, kicked)

		// Close the client's UDP reciever goroutine.
		close(client.udprecv)

		// If the client paniced during authentication, before reaching
		// the ready state, the receiver goroutine will be waiting for
		// a signal telling it that the client is ready to receive 'real'
		// messages from the server.
		//
		// In case of a premature disconnect, close the channel so the
		// receiver routine can exit correctly.
		if client.state == StateClientSentVersion || client.state == StateClientAuthenticated {
			close(client.clientReady)
		}

		client.Printf("Disconnected")
		client.conn.Close()

		client.server.updateCodecVersions(nil)
	}
}

// Disconnect a client (client requested or server shutdown)
func (client *Client) Disconnect() {
	client.disconnect(false)
}

// Disconnect a client (kick/ban)
func (client *Client) ForceDisconnect() {
	client.disconnect(true)
}

// Clear the client's caches
func (client *Client) ClearCaches() {
	for _, vt := range client.voiceTargets {
		vt.ClearCache()
	}
}

// Reject an authentication attempt
func (client *Client) RejectAuth(rejectType mumbleproto.Reject_RejectType, reason string) {
	var reasonString *string = nil
	if len(reason) > 0 {
		reasonString = proto.String(reason)
	}

	client.sendMessage(&mumbleproto.Reject{
		Type:   rejectType.Enum(),
		Reason: reasonString,
	})

	client.ForceDisconnect()
}

// Read a protobuf message from a client
func (client *Client) readProtoMessage() (msg *Message, err error) {
	var (
		length uint32
		kind   uint16
	)

	// Read the message type (16-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &kind)
	if err != nil {
		return
	}

	// Read the message length (32-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &length)
	if err != nil {
		return
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(client.reader, buf)
	if err != nil {
		return
	}

	msg = &Message{
		buf:    buf,
		kind:   kind,
		client: client,
	}

	return
}

// Send permission denied by type
func (c *Client) sendPermissionDeniedType(denyType mumbleproto.PermissionDenied_DenyType) {
	c.sendPermissionDeniedTypeUser(denyType, nil)
}

// Send permission denied by type (and user)
func (c *Client) sendPermissionDeniedTypeUser(denyType mumbleproto.PermissionDenied_DenyType, user *Client) {
	pd := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if user != nil {
		pd.Session = proto.Uint32(uint32(user.Session()))
	}
	err := c.sendMessage(pd)
	if err != nil {
		c.Panicf("%v", err.Error())
		return
	}
}

// Send permission denied by who, what, where
func (c *Client) sendPermissionDenied(who *Client, where *Channel, what uint32) {
	pd := &mumbleproto.PermissionDenied{
		Permission: proto.Uint32(uint32(what)),
		ChannelID:  proto.Uint32(uint32(where.ID)),
		Session:    proto.Uint32(who.Session()),
		Type:       mumbleproto.PermissionDenied_Permission.Enum(),
	}
	err := c.sendMessage(pd)
	if err != nil {
		c.Panicf("%v", err.Error())
		return
	}
}

// Send permission denied fallback
func (client *Client) sendPermissionDeniedFallback(denyType mumbleproto.PermissionDenied_DenyType, version uint32, text string) {
	pd := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if client.Version < version {
		pd.Reason = proto.String(text)
	}
	err := client.sendMessage(pd)
	if err != nil {
		client.Panicf("%v", err.Error())
		return
	}
}

// UDP receive loop
func (client *Client) udpRecvLoop() {
	for buf := range client.udprecv {
		// Received a zero-valued buffer. This means that the udprecv
		// channel was closed, so exit cleanly.
		if len(buf) == 0 {
			return
		}

		kind := (buf[0] >> 5) & 0x07

		switch kind {
		case mumbleproto.UDPMessageVoiceSpeex:
			fallthrough
		case mumbleproto.UDPMessageVoiceCELTAlpha:
			fallthrough
		case mumbleproto.UDPMessageVoiceCELTBeta:
			if client.server.Opus {
				return
			}
			fallthrough
		case mumbleproto.UDPMessageVoiceOpus:
			target := buf[0] & 0x1f
			var counter uint8
			outbuf := make([]byte, 1024)

			incoming := NewPacket(buf[1 : 1+(len(buf)-1)])
			outgoing := NewPacket(outbuf[1 : 1+(len(outbuf)-1)])
			_ = incoming.GetUint32()

			if kind != mumbleproto.UDPMessageVoiceOpus {
				for {
					counter = incoming.Next8()
					incoming.Skip(int(counter & 0x7f))
					if !((counter&0x80) != 0 && incoming.IsValid()) {
						break
					}
				}
			} else {
				size := int(incoming.GetUint16())
				incoming.Skip(size & 0x1fff)
			}

			outgoing.PutUint32(client.Session())
			outgoing.PutBytes(buf[1 : 1+(len(buf)-1)])
			outbuf[0] = buf[0] & 0xe0 // strip target

			if target != 0x1f { // VoiceTarget
				client.server.voiceBroadcast <- &VoiceBroadcast{
					client: client,
					buf:    outbuf[0 : 1+outgoing.Size()],
					target: target,
				}
			} else { // Server loopback
				buf := outbuf[0 : 1+outgoing.Size()]
				err := client.SendUDP(buf)
				if err != nil {
					client.Panicf("Unable to send UDP message: %v", err.Error())
				}
			}

		case mumbleproto.UDPMessagePing:
			err := client.SendUDP(buf)
			if err != nil {
				client.Panicf("Unable to send UDP message: %v", err.Error())
			}
		}
	}
}

// Send buf as a UDP message. If the client does not have
// an established UDP connection, the datagram will be tunelled
// through the client's control channel (TCP).
func (client *Client) SendUDP(buf []byte) error {
	if client.udp {
		crypted := make([]byte, len(buf)+client.crypt.Overhead())
		client.crypt.Encrypt(crypted, buf)
		return client.server.SendUDP(crypted, client.udpaddr)
	} else {
		return client.sendMessage(buf)
	}
	panic("unreachable")
}

// Send a Message to the client.  The Message in msg to the client's
// buffered writer and flushes it when done.
//
// This method should only be called from within the client's own
// sender goroutine, since it serializes access to the underlying
// buffered writer.
func (client *Client) sendMessage(msg interface{}) error {
	buf := new(bytes.Buffer)
	var (
		kind    uint16
		msgData []byte
		err     error
	)

	kind = mumbleproto.MessageType(msg)
	if kind == mumbleproto.MessageUDPTunnel {
		msgData = msg.([]byte)
	} else {
		protoMsg, ok := (msg).(proto.Message)
		if !ok {
			return errors.New("client: exepcted a proto.Message")
		}
		msgData, err = proto.Marshal(protoMsg)
		if err != nil {
			return err
		}
	}

	err = binary.Write(buf, binary.BigEndian, kind)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, uint32(len(msgData)))
	if err != nil {
		return err
	}
	_, err = buf.Write(msgData)
	if err != nil {
		return err
	}

	_, err = client.conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// TLS receive loop
func (client *Client) tlsRecvLoop() {
	for {
		// The version handshake is done, the client has been authenticated and it has received
		// all necessary information regarding the server.  Now we're ready to roll!
		if client.state == StateClientReady {
			// Try to read the next message in the pool
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == io.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}
			// Special case UDPTunnel messages. They're high priority and shouldn't
			// go through our synchronous path.
			if msg.kind == mumbleproto.MessageUDPTunnel {
				client.udp = false
				client.udprecv <- msg.buf
			} else {
				client.server.incoming <- msg
			}
		}

		// The client has responded to our version query. It will try to authenticate.
		if client.state == StateClientSentVersion {
			// Try to read the next message in the pool
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == io.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			client.clientReady = make(chan bool)
			go client.server.handleAuthenticate(client, msg)
			<-client.clientReady

			// It's possible that the client has disconnected in the meantime.
			// In that case, step out of the receiver, since there's nothing left
			// to receive.
			if client.disconnected {
				return
			}

			close(client.clientReady)
			client.clientReady = nil
		}

		// The client has just connected. Before it sends its authentication
		// information we must send it our version information so it knows
		// what version of the protocol it should speak.
		if client.state == StateClientConnected {
			version := &mumbleproto.Version{
				// TODO: What was the point of making a version const when we are going to hardcode it everywhere?
				Version: proto.Uint32(0x10205),
				// TODO: Okay again, why are we not using a const?
				Release:     proto.String("Mumble"),
				CryptoModes: SupportedModes(),
			}
			if client.server.config.BoolValue("SendOSInfo") {
				version.Os = proto.String(runtime.GOOS)
				version.OsVersion = proto.String("(Unknown version)")
			}
			client.sendMessage(version)
			client.state = StateServerSentVersion
			continue
		} else if client.state == StateServerSentVersion {
			msg, err := client.readProtoMessage()
			if err != nil {
				if err == io.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			version := &mumbleproto.Version{}
			err = proto.Unmarshal(msg.buf, version)
			if err != nil {
				client.Panicf("%v", err)
				return
			}

			if version.Version != nil {
				client.Version = *version.Version
			} else {
				client.Version = 0x10200
			}

			if version.Release != nil {
				client.ClientName = *version.Release
			}

			if version.Os != nil {
				client.OSName = *version.Os
			}

			if version.OsVersion != nil {
				client.OSVersion = *version.OsVersion
			}

			// Extract the client's supported crypto mode.
			// If the client does not pick a crypto mode
			// itself, use an invalid mode (the empty string)
			// as its requested mode. This is effectively
			// a flag asking for the default crypto mode.
			requestedMode := ""
			if len(version.CryptoModes) > 0 {
				requestedMode = version.CryptoModes[0]
			}

			// Check if the requested crypto mode is supported
			// by us. If not, fall back to the default crypto
			// mode.
			supportedModes := SupportedModes()
			ok := false
			for _, mode := range supportedModes {
				if requestedMode == mode {
					ok = true
					break
				}
			}
			if !ok {
				requestedMode = "OCB2-AES128"
			}

			client.CryptoMode = requestedMode
			client.state = StateClientSentVersion
		}
	}
}

func (client *Client) sendChannelList() {
	client.sendChannelTree(client.server.RootChannel())
}

func (client *Client) sendChannelTree(channel *Channel) {
	chanstate := &mumbleproto.ChannelState{
		ChannelID: proto.Uint32(uint32(channel.ID)),
		Name:      proto.String(channel.Name),
	}
	if channel.parent != nil {
		chanstate.Parent = proto.Uint32(uint32(channel.parent.ID))
	}

	if channel.HasDescription() {
		if client.Version >= 0x10202 {
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		} else {
			// TODO: Can we please just use a key/value store? Orrr the fucking SQL database we implemented? For fucks sake
			buf, err := BlobStoreGet(channel.DescriptionBlob)
			if err != nil {
				panic("Blobstore error.")
			}
			chanstate.Description = proto.String(string(buf))
		}
	}

	if channel.IsTemporary() {
		chanstate.Temporary = proto.Bool(true)
	}

	chanstate.Position = proto.Int32(int32(channel.Position))

	links := []uint32{}
	for cid, _ := range channel.Links {
		links = append(links, uint32(cid))
	}
	chanstate.Links = links

	err := client.sendMessage(chanstate)
	if err != nil {
		client.Panicf("%v", err)
	}

	for _, subchannel := range channel.children {
		client.sendChannelTree(subchannel)
	}
}

// Try to do a crypto resync
func (client *Client) cryptResync() {
	client.Debugf("requesting crypt resync")
	goodElapsed := time.Now().Unix() - client.crypt.LastGoodTime
	if goodElapsed > 5 {
		requestElapsed := time.Now().Unix() - client.lastResync
		if requestElapsed > 5 {
			client.lastResync = time.Now().Unix()
			cryptsetup := &mumbleproto.CryptSetup{}
			err := client.sendMessage(cryptsetup)
			if err != nil {
				client.Panicf("%v", err)
			}
		}
	}
}
