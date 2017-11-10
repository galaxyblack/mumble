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
	//logForwarder *LogForwarder

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
	// Also lets isolate out the public and private so its easier to read
	Username string
	Email    string
	Channel  *Channel
	Context
	SelfMute        bool
	SelfDeaf        bool
	Mute            bool
	Deaf            bool
	Suppress        bool
	PrioritySpeaker bool
	Recording       bool
	PluginContext   []byte
	PluginIdentity  string
	session         uint32
	certificateHash string
	tokens          []string

	// mumbleprotocol
	Actor uint32
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
func (client *Client) UserID() uint32 {
	// TODO: Third fucking time we did this check, come on, lets make validating functions and use them for consistent functionality, smaller code footprint and easier testing!
	if client.user == nil {
		// TODO: No, lets not plz, was doing -1 but doing 0 for now just to comply and build
		return 0
	}
	// TODO: Seriously why are we returning it as an int? Just use a bool and only have uints32 so we dont convert 500 times
	return client.user.ID
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
	// TODO: There seems to be a lot of assigning local variables when its not erally ncessary
	tlsConnection := client.connection.(*tls.Conn)
	state := tlsConnection.ConnectionState()
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
		close(client.udpReceive)

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
		client.connection.Close()

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
	for _, voiceTarget := range client.voiceTargets {
		voiceTarget.ClearCache()
	}
}

// Reject an authentication attempt
func (client *Client) RejectAuth(rejectType mumbleproto.Reject_RejectType, reason string) {
	var reasonString *string = nil
	// TODO: Validation, so new function, and checking empty doesnt require counting all chars in reason
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
func (client *Client) readProtocolMessage() (message *Message, err error) {
	// TODO: Put this in the struct!!!!!!!
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

	buffer := make([]byte, length)
	_, err = io.ReadFull(client.reader, buffer)
	if err != nil {
		return
	}

	// TODO: Break up this logic!
	message = &Message{
		buffer: buffer,
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
	permissionDenied := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if user != nil {
		permissionDenied.Session = proto.Uint32(user.Session())
	}
	err := c.sendMessage(permissionDenied)
	if err != nil {
		c.Panicf("%v", err.Error())
		return
	}
}

// Send permission denied by who, what, where
func (c *Client) sendPermissionDenied(who *Client, where *Channel, what uint32) {
	permissionDenied := &mumbleproto.PermissionDenied{
		Permission: proto.Uint32(uint32(what)),
		ChannelID:  proto.Uint32(where.ID),
		Session:    proto.Uint32(who.Session()),
		Type:       mumbleproto.PermissionDenied_Permission.Enum(),
	}
	err := c.sendMessage(permissionDenied)
	if err != nil {
		c.Panicf("%v", err.Error())
		return
	}
}

// Send permission denied fallback
func (client *Client) sendPermissionDeniedFallback(denyType mumbleproto.PermissionDenied_DenyType, version uint32, text string) {
	permissionDenied := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if client.Version < version {
		permissionDenied.Reason = proto.String(text)
	}
	err := client.sendMessage(permissionDenied)
	if err != nil {
		client.Panicf("%v", err.Error())
		return
	}
}

// UDP receive loop
func (client *Client) udpReceiveLoop() {
	for buffer := range client.udpReceive {
		// Received a zero-valued buffer. This means that the udpReceive
		// channel was closed, so exit cleanly.
		// TODO: This is a validation, so it should be broken off into its own function
		// TODO: Check if len check or just index[0] check is faster
		// TODO: WOULD THE BUFFER BE EMPTY OR NIL? Because both ahve 0 length and why count past 0 when finding out if its just nil or empty?
		if len(buffer) == 0 {
			return
		}

		kind := (buffer[0] >> 5) & 0x07

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
			target := buffer[0] & 0x1f
			var counter uint8
			outBuffer := make([]byte, 1024)

			incoming := NewPacket(buffer[1 : 1+(len(buffer)-1)])
			outgoing := NewPacket(outBuffer[1 : 1+(len(outBuffer)-1)])
			// TODO: Have a feeling this is not a good thing to keep
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
			outgoing.PutBytes(buffer[1 : 1+(len(buffer)-1)])
			outBuffer[0] = buffer[0] & 0xe0 // strip target

			if target != 0x1f { // VoiceTarget
				// TODO: There must be a reason to establish this fucking struct previously to this
				client.server.voiceBroadcast <- &VoiceBroadcast{
					client: client,
					buffer: outBuffer[0 : 1+outgoing.Size()],
					target: target,
				}
			} else { // Server loopback
				buffer := outBuffer[0 : 1+outgoing.Size()]
				// TODO: We not really going to return this err?
				err := client.SendUDP(buffer)
				if err != nil {
					client.Panicf("Unable to send UDP message: %v", err.Error())
				}
			}

		case mumbleproto.UDPMessagePing:
			err := client.SendUDP(buffer)
			if err != nil {
				client.Panicf("Unable to send UDP message: %v", err.Error())
			}
		}
	}
}

// Send buffer as a UDP message. If the client does not have
// an established UDP connection, the datagram will be tunelled
// through the client's control channel (TCP).
func (client *Client) SendUDP(buffer []byte) error {
	if client.udp {
		crypted := make([]byte, len(buffer)+client.crypt.Overhead())
		client.crypt.Encrypt(crypted, buffer)
		return client.server.SendUDP(crypted, client.udpAddr)
	} else {
		return client.sendMessage(buffer)
	}
	panic("unreachable")
}

// Send a Message to the client.  The Message in message to the client's
// buffered writer and flushes it when done.
//
// This method should only be called from within the client's own
// sender goroutine, since it serializes access to the underlying
// buffered writer.
// TODO: Why not actually have a message interface intead of initialziing inline in the sendMesssage. There must be uses in individual validations and much more
func (client *Client) sendMessage(message interface{}) error {
	buffer := new(bytes.Buffer)
	var (
		kind        uint16
		messageData []byte
		err         error
	)

	kind = mumbleproto.MessageType(message)
	if kind == mumbleproto.MessageUDPTunnel {
		messageData = message.([]byte)
	} else {
		protoMessage, ok := (message).(proto.Message)
		if !ok {
			return errors.New("client: exepcted a proto.Message")
		}
		messageData, err = proto.Marshal(protoMessage)
		if err != nil {
			return err
		}
	}

	err = binary.Write(buffer, binary.BigEndian, kind)
	// TODO: if these validations were moved into their own functions would be easy to test and could gather all the errors and present them together instead of having the user fix 1 by 1 like a loser
	if err != nil {
		return err
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(len(messageData)))
	if err != nil {
		return err
	}
	_, err = buffer.Write(messageData)
	if err != nil {
		return err
	}

	_, err = client.connection.Write(buffer.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// TLS receive loop
func (client *Client) tlsReceiveLoop() {
	for {
		// The version handshake is done, the client has been authenticated and it has received
		// all necessary information regarding the server.  Now we're ready to roll!
		if client.state == StateClientReady {
			// Try to read the next message in the pool
			message, err := client.readProtocolMessage()
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
			if message.kind == mumbleproto.MessageUDPTunnel {
				client.udp = false
				client.udpReceive <- message.buffer
			} else {
				client.server.incoming <- message
			}
		}

		// The client has responded to our version query. It will try to authenticate.
		if client.state == StateClientSentVersion {
			// Try to read the next message in the pool
			message, err := client.readProtocolMessage()
			if err != nil {
				if err == io.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			client.clientReady = make(chan bool)
			go client.server.handleAuthenticate(client, message)
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
				Release:     proto.String("Mumble Server"),
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
			message, err := client.readProtocolMessage()
			if err != nil {
				if err == io.EOF {
					client.Disconnect()
				} else {
					client.Panicf("%v", err)
				}
				return
			}

			version := &mumbleproto.Version{}
			err = proto.Unmarshal(message.buffer, version)
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
