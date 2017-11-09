package protocol

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"mumble/protocol/mumbleproto"
)

// The default port a Murmur server listens on
// TODO: These should not be constants :( this should be defined by the user or have a default value :( :( seriously this kind of programming makes me sad ;_;
// Like a default server struct with these objects loaded as defaults that are overriden by config then environmental variable then flags args.
// Otherwise we are just wasting memory if anything is NOT default :(
const (
	DefaultPort          = 64738
	UDPPacketSize        = 1024
	LogOpsBeforeSync     = 100
	CeltCompatBitstream  = -2147483637
	StateClientConnected = iota
	StateServerSentVersion
	StateClientSentVersion
	StateClientAuthenticated
	StateClientReady
	StateClientDead
)

type KeyValuePair struct {
	Key   string
	Value string
	Reset bool
}

// A Mumble (Murmur) server instance
// TODO: Exactly its a server instance, so why are we not storing server configuration values here!!!!!
// if done correclty, this can support clusters
type Server struct {
	ID uint32

	// TODO: Do MORE cleanup on these names, follow Go convention, and make it readable so, we dont have to have inside knowledge to understand our server struct, pretty important data type one would hope
	tcpListener   *net.TCPListener
	tlsListener   net.Listener
	udpConnection *net.UDPConn
	tlsConfig     *tls.Config
	bye           chan bool
	waitGroup     sync.WaitGroup
	isRunning     bool

	incoming       chan *Message
	voiceBroadcast chan *VoiceBroadcast
	configUpdate   chan *KeyValuePair
	// TODO: What? Can't be needed
	tempRemove chan *Channel

	// Signals to the server that a client has been successfully
	// authenticated.
	clientAuthenticated chan *Client

	// Server configuration
	config *Config

	// Clients
	clients map[uint32]*Client

	// Host, host/port -> client mapping
	// TODO: A host+port combo is generally called just hostname
	// TODO: We should just use full variable names that are readable, this is compiled not JS
	hostMutex       sync.Mutex
	hostClients     map[string][]*Client
	hostnameClients map[string]*Client

	// Codec information
	AlphaCodec       int32
	BetaCodec        int32
	PreferAlphaCodec bool
	Opus             bool

	// Channels
	Channels   map[int]*Channel
	nextChanID int

	// Users
	Users       map[uint32]*User
	UserCertMap map[string]*User
	UserNameMap map[string]*User
	nextUserID  uint32

	// Sessions
	pool *SessionPool

	// Freezer
	// TODO: This freezer stuff is really bad, I would prefer to just use something like bolt, an embedded key/value store and let it do this
	// that way we can avoid writing the same code worse
	numLogOps int
	freezeLog *Log

	// Bans
	banLock sync.RWMutex
	Bans    []Ban

	// Logging
	*log.Logger
}

type clientLogForwarder struct {
	client *Client
	logger *log.Logger
}

func (logForwarder clientLogForwarder) Write(incoming []byte) (int, error) {
	buffer := new(bytes.Buffer)
	buffer.WriteString(fmt.Sprintf("<%v:%v(%v)> ", logForwarder.client.Session(), lf.client.ShownName(), lf.client.UserId()))
	buffer.Write(incoming)
	logForwarder.logger.Output(3, buffer.String())
	return len(incoming), nil
}

// Allocate a new Murmur instance
// TODO: Every other function uses the local name server, why is this using s? Consistency is always best practice
// TODO: What? Why are we passing the ID? Generate a god damn ID, don't have us pass it, get all other shit from config, you want a server name? CONFIG!
// TODO: Also maybe break up into new and init? Ruby had some good ideas with that
func NewServer(id int64) (server *Server, err error) {
	server = new(Server)
	server.ID = id

	// TODO: What the fuck? No pull this directly from JSON. Rule is: Runtime configuration > Environmental Variables > Config > Default values.
	// this is how you make software that is not annoying as fuck to use for people you know. like not shitty, works without any config, but it can generate a blank from default if nothing is defined and easily overridden in the expected way.
	server.config = serverConf.New(nil)

	// TODO: Whats the point of the SQL db if we arent going to put the users there? Lets move this to key/value, this is insane
	// BoltDB? Fast and on-disk like the freeze shit or completely in memory database that has better way of organizing than just maps/hashes  AT THE VERY LEAST, LETS NOT USE STRING FUCKING IDS FOR FUCKS SAKE! AND LETS USE PREFIX radix based lookup? is it worth it to use a pure go implementation and cut out more code?
	server.Users = make(map[uint32]*User)
	server.UserCertMap = make(map[string]*User)
	server.UserNameMap = make(map[string]*User)
	server.Users[0], err = NewUser(0, "SuperUser")
	server.UserNameMap["SuperUser"] = server.Users[0]
	server.nextUserID = 1

	server.Channels = make(map[int]*Channel)
	server.Channels[0] = NewChannel(0, "Root")
	server.nextChanID = 1

	server.Logger = log.New(&logtarget.Target, fmt.Sprintf("[%v] ", server.ID), log.LstdFlags|log.Lmicroseconds)

	return
}

// Debugf implements debug-level printing for Servers.
func (server *Server) Debugf(format string, v ...interface{}) {
	server.Printf(format, v...)
}

// Get a pointer to the root channel
func (server *Server) RootChannel() *Channel {
	root, exists := server.Channels[0]
	if !exists {
		server.Fatalf("Not Root channel found for server")
	}
	return root
}

// Set password as the new SuperUser password
func (server *Server) SetSuperUserPassword(password string) {
	saltBytes := make([]byte, 24)
	_, err := rand.Read(saltBytes)
	if err != nil {
		server.Fatalf("Unable to read from crypto/rand: %v", err)
	}

	salt := hex.EncodeToString(saltBytes)
	hasher := sha1.New()
	hasher.Write(saltBytes)
	hasher.Write([]byte(password))
	digest := hex.EncodeToString(hasher.Sum(nil))

	// Could be racy, but shouldn't really matter...
	// TODO: No this does matter, jesus fucking christ, it fucking matters!
	// TODO: Also don't use sha1, come on, its 2017
	key := "SuperUserPassword"
	val := "sha1$" + salt + "$" + digest
	server.cfg.Set(key, val)
	server.cfgUpdate <- &KeyValuePair{Key: key, Value: val}
}

// Check whether password matches the set SuperUser password.
// TODO: Add shared secrets, ephemeral keying, OTP, 2nd-factor, etc
func (server *Server) CheckSuperUserPassword(password string) bool {
	parts := strings.Split(server.cfg.StringValue("SuperUserPassword"), "$")
	if len(parts) != 3 {
		return false
	}

	if len(parts[2]) == 0 {
		return false
	}

	var h hash.Hash
	switch parts[0] {
	case "sha1":
		h = sha1.New()
	default:
		// no such hash
		return false
	}

	// salt
	if len(parts[1]) > 0 {
		saltBytes, err := hex.DecodeString(parts[1])
		if err != nil {
			server.Fatalf("Unable to decode salt: %v", err)
		}
		h.Write(saltBytes)
	}

	// password
	h.Write([]byte(password))

	sum := hex.EncodeToString(h.Sum(nil))
	// TODO: Use DeepCompare not just ==
	if parts[2] == sum {
		return true
	}

	return false
}

// Called by the server to initiate a new client connection.
func (server *Server) handleIncomingClient(connection net.Conn) (err error) {
	client := new(Client)
	// TODO: Is it necessary to pull addr out into a variable THAT IS NOT FUCKING STORED INSIDE THE CLIENT STRUT? FUCKING HELL!
	// Also lets again break out validations for easier testing and cleaner more readable implementation and easier potential for reuse. For example regex for ip address format validation? 1 function we could use quite a few places
	addr := connection.RemoteAddr()

	if addr == nil {
		err = errors.New("Unable to extract address for client.")
		return
	}

	client.logForwarder = &clientLogForwarder{client, server.Logger}
	client.Logger = log.New(client.logForwarder, "", 0)

	client.session = server.pool.Get()
	client.Printf("New connection: %v (%v)", connection.RemoteAddr(), client.Session())

	client.tcpAddr = addr.(*net.TCPAddr)
	client.server = server
	// TODO: Why bother setting a connection variable then assigning it to client? seems quite a bit
	client.connection = connection
	client.reader = bufio.NewReader(client.connection) // TODO: Feels like this could be done better

	client.state = StateClientConnected

	client.udpReceive = make(chan []byte)
	client.voiceTargets = make(map[uint32]*VoiceTarget)

	client.user = nil // TODO: what? why are we defining nils?

	// Extract user's cert hash
	tlsConnection := client.connection.(*tls.Conn)
	err = tlsConnection.Handshake()
	if err != nil {
		client.Printf("TLS handshake failed: %v", err)
		client.Disconnect()
		return
	}

	state := tlsc.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		// TODO: Sha1? No thank you. Same library has better security hashing, no reason to do this.
		hash := sha1.New()
		hash.Write(state.PeerCertificates[0].Raw)
		sum := hash.Sum(nil)
		client.certHash = hex.EncodeToString(sum)
	}

	// Check whether the client's cert hash is banned
	if server.IsCertHashBanned(client.CertHash()) {
		client.Printf("Certificate hash is banned")
		client.Disconnect()
		return
	}

	// Launch network readers
	go client.tlsReceiveLoop()
	go client.udpReceiveLoop()

	return
}

// Remove a disconnected client from the server's
// internal representation.
// TODO: Bring consistency with camel-case naming, its very inconsistent.
func (server *Server) RemoveClient(client *Client, kicked bool) {
	server.hostMutex.Lock()
	host := client.tcpAddr.IP.String()
	oldClients := server.hostClients[host]
	newClients := []*Client{}
	for _, hostClient := range oldClients {
		if hostClient != client {
			newClients = append(newClients, hostClient)
		}
	}
	server.hostClients[host] = newClients
	if client.udpAddr != nil {
		delete(server.hostnameClients, client.udpAddr.String())
	}
	server.hostMutex.Unlock()

	delete(server.clients, client.Session())
	server.pool.Reclaim(client.Session())

	// Remove client from channel
	channel := client.Channel
	if channel != nil {
		channel.RemoveClient(client)
	}

	// If the user was not kicked, broadcast a UserRemove message.
	// If the user is disconnect via a kick, the UserRemove message has already been sent
	// at this point.
	// TODO: Why is kicked check not its own function? Why is it a local variable and not a attribute of the user?
	if !kicked && client.state > StateClientAuthenticated {
		err := server.broadcastProtoMessage(&mumbleproto.UserRemove{
			Session: uint32(client.Session()),
		})
		if err != nil {
			server.Panic("Unable to broadcast UserRemove message for disconnected client.")
		}
	}
}

// Add a new channel to the server. Automatically assign it a channel ID.
func (server *Server) AddChannel(name string) (channel *Channel) {
	channel = NewChannel(server.nextChannelID, name)
	server.Channels[channel.ID] = channel
	// TODO: Itd be nicer to use non-consecutive/iteratable
	server.nextChannelID += 1

	return
}

// Remove a channel from the server.
func (server *Server) RemoveChanel(channel *Channel) {
	// TODO: Move validaiton to its own function, see every other comment for the various reasons
	if channel.ID == 0 {
		server.Printf("Attempted to remove root channel.")
		return
	}

	delete(server.Channels, channel.ID)
}

// Link two channels
func (server *Server) LinkChannels(channel *Channel, other *Channel) {
	channel.Links[other.ID] = other
	other.Links[channel.ID] = channel
}

// Unlink two channels
func (server *Server) UnlinkChannels(channel *Channel, other *Channel) {
	delete(channel.Links, other.ID)
	delete(other.Links, channel.ID)
}

// This is the synchronous handler goroutine.
// Important control channel messages are routed through this Goroutine
// to keep server state synchronized.
func (server *Server) handlerLoop() {
	// TODO: Are we short polling every hour? Why tick based over RT scheduling intervals?
	regTick := time.Tick(time.Hour)
	for {
		select {
		// We're done. Stop the server's event handler
		case <-server.bye:
			return
		// Control channel messages
		case msg := <-server.incoming:
			client := msg.client
			server.handleIncomingMessage(client, msg)
		// Voice broadcast
		case broadcast := <-server.voiceBroadcast:
			if broadcast.target == 0 { // Current channel
				channel := vb.client.Channel
				for _, client := range channel.clients {
					if client != broadcast.client {
						err := client.SendUDP(broadcast.buf)
						if err != nil {
							client.Panicf("Unable to send UDP: %v", err)
						}
					}
				}
			} else {
				target, ok := broadcast.client.voiceTargets[uint32(broadcast.target)]
				if !ok {
					continue
				}

				target.SendVoiceBroadcast(broadcast)
			}
		// Remove a temporary channel
		case temporaryChannel := <-server.temporaryRemove:
			if temporaryChannel.IsEmpty() {
				server.RemoveChannel(temporaryChannel)
			}
		// Finish client authentication. Send post-authentication
		// server info.
		case client := <-server.clientAuthenticated:
			server.finishAuthenticate(client)
		// Disk freeze config update
		case kvp := <-server.configUpdate:
			if !kvp.Reset {
				server.UpdateConfig(kvp.Key, kvp.Value)
			} else {
				server.ResetConfig(kvp.Key)
			}

		// Server registration update
		// Tick every hour + a minute offset based on the server id.
		case <-regtick:
			server.RegisterPublicServer()
		}

		// Check if its time to sync the server state and re-open the log
		// TODO: Why? And if we are doing this lets just use an embedded DB that can handle this logic, simplify our code and reduce bugs by sharing solutions with the community
		if server.numLogs >= LogsBeforeSync {
			server.Print("Writing full server snapshot to disk")
			err := server.FreezeToFile()
			if err != nil {
				server.Fatal(err)
			}
			server.numLogs = 0
			server.Print("Wrote full server snapshot to disk")
		}
	}
}

// Handle an Authenticate protobuf message.  This is handled in a separate
// goroutine to allow for remote authenticators that are slow to respond.
//
// Once a user has been authenticated, it will ping the server's handler
// routine, which will call the finishAuthenticate method on Server which
// will send the channel tree, user list, etc. to the client.
func (server *Server) handleAuthenticate(client *Client, msg *Message) {
	// Is this message not an authenticate message? If not, discard it...
	if msg.kind != mumbleproto.MessageAuthenticate {
		client.Panic("Unexpected message. Expected Authenticate.")
		return
	}

	auth := &mumbleproto.Authenticate{}
	err := proto.Unmarshal(msg.buffer, auth)
	if err != nil {
		client.Panic("Unable to unmarshal Authenticate message.")
		return
	}

	// Set access tokens. Clients can set their access tokens any time
	// by sending an Authenticate message with he contents of their new
	// access token list.
	client.tokens = auth.Tokens
	server.ClearCaches()

	if client.state >= StateClientAuthenticated {
		return
	}

	// Did we get a username?
	if auth.Username == nil || len(*auth.Username) == 0 {
		// TODO: Can this be changed to follow camel-case convention, since we are matching C++ server it may be impossible.
		client.RejectAuth(mumbleproto.Reject_InvalidUsername, "Please specify a username to log in")
		return
	}

	client.Username = *auth.Username

	if client.Username == "SuperUser" {
		if auth.Password == nil {
			client.RejectAuth(mumbleproto.Reject_WrongUserPW, "")
			return
		} else {
			if server.CheckSuperUserPassword(*auth.Password) {
				ok := false
				client.user, ok = server.UserNameMap[client.Username]
				if !ok {
					client.RejectAuth(mumbleproto.Reject_InvalidUsername, "")
					return
				}
			} else {
				client.RejectAuth(mumbleproto.Reject_WrongUserPW, "")
				return
			}
		}
	} else {
		// First look up registration by name.
		user, exists := server.UserNameMap[client.Username]
		if exists {
			if client.HasCertificate() && user.CertHash == client.CertHash() {
				client.user = user
			} else {
				client.RejectAuth(mumbleproto.Reject_WrongUserPW, "Wrong certificate hash")
				return
			}
		}

		// Name matching didn't do.  Try matching by certificate.
		if client.user == nil && client.HasCertificate() {
			user, exists := server.UserCertMap[client.CertHash()]
			if exists {
				client.user = user
			}
		}
	}

	// Setup the cryptstate for the client.
	err = client.crypt.GenerateKey(client.CryptoMode)
	if err != nil {
		client.Panicf("%v", err)
		return
	}

	// Send CryptState information to the client so it can establish an UDP connection,
	// if it wishes.
	client.lastResync = time.Now().Unix()
	err = client.sendMessage(&mumbleproto.CryptSetup{
		Key:         client.crypt.Key,
		ClientNonce: client.crypt.DecryptIV,
		ServerNonce: client.crypt.EncryptIV,
	})
	if err != nil {
		client.Panicf("%v", err)
	}

	// Add codecs
	client.codecs = auth.CeltVersions
	client.opus = auth.GetOpus()

	client.state = StateClientAuthenticated
	server.clientAuthenticated <- client
}

// The last part of authentication runs in the server's synchronous handler.
func (server *Server) finishAuthenticate(client *Client) {
	// If the client succeeded in proving to the server that it should be granted
	// the credentials of a registered user, do some sanity checking to make sure
	// that user isn't already connected.
	//
	// If the user is already connected, try to check whether this new client is
	// connecting from the same IP address. If that's the case, disconnect the
	// previous client and let the new guy in.
	if client.user != nil {
		found := false
		// TODO: This type of comparison should be deep, and itd be better to just use an embedded database again. Or the SQL database
		for _, connectedClient := range server.clients {
			if connectedClient.UserID() == client.UserID() {
				found = true
				break
			}
		}
		// The user is already present on the server.
		if found {
			// todo(mkrautz): Do the address checking.
			client.RejectAuth(mumbleproto.Reject_UsernameInUse, "A client is already connected using those credentials.")
			return
		}

		// No, that user isn't already connected. Move along.
	}

	// Add the client to the connected list
	server.clients[client.Session()] = client

	// Warn clients without CELT support that they might not be able to talk to everyone else.
	if len(client.codecs) == 0 {
		client.codecs = []int32{CeltCompatBitstream}
		server.Printf("Client %v connected without CELT codecs. Faking compat bitstream.", client.Session())
		if server.Opus && !client.opus {
			client.sendMessage(&mumbleproto.TextMessage{
				Session: []uint32{client.Session()},
				Message: proto.String("<strong>WARNING:</strong> Your client doesn't support the CELT codec, you won't be able to talk to or hear most clients. Please make sure your client was built with CELT support."),
			})
		}
	}

	// First, check whether we need to tell the other connected
	// clients to switch to a codec so the new guy can actually speak.
	server.updateCodecVersions(client)
	client.sendChannelList()

	// Add the client to the host slice for its host address.
	host := client.tcpAddr.IP.String()
	server.hostMutex.Lock()
	server.hostClients[host] = append(server.hostClients[host], client)
	server.hostMutex.Unlock()

	channel := server.RootChannel()
	if client.IsRegistered() {
		lastChannel := server.Channels[client.user.LastChannelID]
		if lastChannel != nil {
			channel = lastChannel
		}
	}

	userstate := &mumbleproto.UserState{
		Session:   proto.Uint32(client.Session()),
		Name:      proto.String(client.ShownName()),
		ChannelID: proto.Uint32(uint32(channel.ID)),
	}

	if client.HasCertificate() {
		userstate.Hash = proto.String(client.CertificateHash())
	}

	if client.IsRegistered() {
		userstate.UserID = proto.Uint32(uint32(client.UserID()))
		if client.user.HasTexture() {
			// Does the client support blobs?
			if client.Version >= 0x10203 {
				userState.TextureHash = client.user.TextureBlobHashBytes()
			} else {
				buffer, err := blobStore.Get(client.user.TextureBlob)
				if err != nil {
					server.Panicf("Blobstore error: %v", err.Error())
				}
				userState.Texture = buffer
			}
		}

		if client.user.HasComment() {
			// Does the client support blobs?
			if client.Version >= 0x10203 {
				userState.CommentHash = client.user.CommentBlobHashBytes()
			} else {
				buffer, err := blobStore.Get(client.user.CommentBlob)
				if err != nil {
					server.Panicf("Blobstore error: %v", err.Error())
				}
				userstate.Comment = proto.String(string(buffer))
			}
		}
	}

	server.userEnterChannel(client, channel, userState)
	if err := server.broadcastProtoMessage(userState); err != nil {
		// Server panic?
	}

	server.sendUserList(client)

	sync := &mumbleproto.ServerSync{}
	// TODO: Can we have key based sessions? Making them a bit harder to iterate and allow prefix tree lookups?
	sync.Session = client.Session()
	sync.MaxBandwidth = server.config.MaxBandwidth
	sync.WelcomeText = server.config.WelcomeText
	if client.IsSuperUser() {
		sync.Permissions = uint64(acl.AllPermissions)
	} else {
		// fixme(mkrautz): previously we calculated the user's
		// permissions and sent them to the client in here. This
		// code relied on our ACL cache, but that has been temporarily
		// thrown out because of our ACL handling code moving to its
		// own package.
		sync.Permissions = nil
	}
	if err := client.sendMessage(sync); err != nil {
		client.Panicf("%v", err)
		return
	}

	err := client.sendMessage(&mumbleproto.ServerConfig{
		AllowHtml:          server.config.AllowHTML,
		MessageLength:      server.config.MaxTextMessageLength,
		ImageMessageLength: server.config.MaxImageMessageLength,
	})
	if err != nil {
		client.Panicf("%v", err)
		return
	}

	client.state = StateClientReady
	client.clientReady <- true
}

func (server *Server) updateCodecVersions(connecting *Client) {
	codecusers := map[int32]int{}
	var (
		winner     int32
		count      int
		users      int
		opus       int
		enableOpus bool
		txtMsg     *mumbleproto.TextMessage = &mumbleproto.TextMessage{
			Message: "<strong>WARNING:</strong> Your client doesn't support the Opus codec the server is switching to, you won't be able to talk or hear anyone. Please upgrade to a client with Opus support.",
		}
	)

	for _, client := range server.clients {
		users++
		if client.opus {
			opus++
		}
		for _, codec := range client.codecs {
			codecUsers[codec] += 1
		}
	}

	for codec, users := range codecUsers {
		if users > count {
			count = users
			winner = codec
		}
		if users == count && codec > winner {
			winner = codec
		}
	}

	var current int32
	if server.PreferAlphaCodec {
		current = server.AlphaCodec
	} else {
		current = server.BetaCodec
	}

	// If all users are opus enabled, then enable opus
	enableOpus = (users == opus)

	if winner != current {
		if winner == CeltCompatBitstream {
			server.PreferAlphaCodec = true
		} else {
			server.PreferAlphaCodec = !server.PreferAlphaCodec
		}

		if server.PreferAlphaCodec {
			server.AlphaCodec = winner
		} else {
			server.BetaCodec = winner
		}
	} else if server.Opus == enableOpus {
		if server.Opus && connecting != nil && !connecting.opus {
			txtMsg.Session = []uint32{connecting.Session()}
			connecting.sendMessage(txtMsg)
		}
		return
	}

	server.Opus = enableOpus

	err := server.broadcastProtoMessage(&mumbleproto.CodecVersion{
		Alpha:       proto.Int32(server.AlphaCodec),
		Beta:        proto.Int32(server.BetaCodec),
		PreferAlpha: proto.Bool(server.PreferAlphaCodec),
		Opus:        proto.Bool(server.Opus),
	})
	if err != nil {
		server.Printf("Unable to broadcast.")
		return
	}

	if server.Opus {
		for _, client := range server.clients {
			if !client.opus && client.state == StateClientReady {
				textMsg.Session = []uint32{connecting.Session()}
				err := client.sendMessage(textMsg)
				if err != nil {
					client.Panicf("%v", err)
				}
			}
		}
		if connecting != nil && !connecting.opus {
			textMsg.Session = []uint32{connecting.Session()}
			connecting.sendMessage(textMsg)
		}
	}

	server.Printf("CELT codec switch %#x %#x (PreferAlpha %v) (Opus %v)", uint32(server.AlphaCodec), uint32(server.BetaCodec), server.PreferAlphaCodec, server.Opus)
	return
}

func (server *Server) sendUserList(client *Client) {
	for _, connectedClient := range server.clients {
		if connectedClient.state != StateClientReady {
			continue
		}
		if connectedClient == client {
			continue
		}

		userstate := &mumbleproto.UserState{
			Session:   proto.Uint32(connectedClient.Session()),
			Name:      proto.String(connectedClient.ShownName()),
			ChannelID: proto.Uint32(uint32(connectedClient.Channel.ID)),
		}

		if connectedClient.HasCertificate() {
			userstate.Hash = proto.String(connectedClient.CertHash())
		}

		if connectedClient.IsRegistered() {
			userstate.UserID = proto.Uint32(uint32(connectedClient.UserID()))

			if connectedClient.user.HasTexture() {
				// Does the client support blobs?
				if client.Version >= 0x10203 {
					userState.TextureHash = connectedClient.user.TextureBlobHashBytes()
				} else {
					buffer, err := BlobStoreGet(connectedClient.user.TextureBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err.Error())
					}
					userState.Texture = buffer
				}
			}

			if connectedClient.user.HasComment() {
				// Does the client support blobs?
				// TODO: Break down client feature checking into individual fucntions to simplify the thresholds
				if client.Version >= 0x10203 {
					userState.CommentHash = connectedClient.user.CommentBlobHashBytes()
				} else {
					buffer, err := BlobStoreGet(connectedClient.user.CommentBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err.Error())
					}
					userState.Comment = proto.String(string(buffer))
				}
			}
		}

		if connectedClient.Mute {
			userstate.Mute = proto.Bool(true)
		}
		if connectedClient.Suppress {
			userstate.Suppress = proto.Bool(true)
		}
		if connectedClient.SelfMute {
			userstate.SelfMute = proto.Bool(true)
		}
		if connectedClient.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
		}
		if connectedClient.PrioritySpeaker {
			userstate.PrioritySpeaker = proto.Bool(true)
		}
		if connectedClient.Recording {
			userstate.Recording = proto.Bool(true)
		}
		if connectedClient.PluginContext != nil || len(connectedClient.PluginContext) > 0 {
			userstate.PluginContext = connectedClient.PluginContext
		}
		if len(connectedClient.PluginIdentity) > 0 {
			userstate.PluginIdentity = proto.String(connectedClient.PluginIdentity)
		}

		err := client.sendMessage(userState)
		if err != nil {
			// Server panic?
			continue
		}
	}
}

// Send a client its permissions for channel.
func (server *Server) sendClientPermissions(client *Client, channel *Channel) {
	// No caching for SuperUser
	if client.IsSuperUser() {
		return
	}

	// fixme(mkrautz): re-add when we have ACL caching
	return

	perm := acl.Permission(acl.NonePermission)
	client.sendMessage(&mumbleproto.PermissionQuery{
		ChannelID:   uint32(channel.ID),
		Permissions: uint32(permission),
	})
}

type ClientPredicate func(client *Client) bool

func (server *Server) broadcastProtoMessageWithPredicate(msg interface{}, clientcheck ClientPredicate) error {
	for _, client := range server.clients {
		if !clientCheck(client) {
			continue
		}
		if client.state < StateClientAuthenticated {
			continue
		}
		err := client.sendMessage(msg)
		if err != nil {
			return err
		}
	}

	return nil
}

func (server *Server) broadcastProtoMessage(msg interface{}) (err error) {
	err = server.broadcastProtoMessageWithPredicate(msg, func(client *Client) bool { return true })
	return
}

func (server *Server) handleIncomingMessage(client *Client, msg *Message) {
	switch msg.kind {
	case mumbleproto.MessageAuthenticate:
		server.handleAuthenticate(msg.client, msg)
	case mumbleproto.MessagePing:
		server.handlePingMessage(msg.client, msg)
	case mumbleproto.MessageChannelRemove:
		server.handleChannelRemoveMessage(msg.client, msg)
	case mumbleproto.MessageChannelState:
		server.handleChannelStateMessage(msg.client, msg)
	case mumbleproto.MessageUserState:
		server.handleUserStateMessage(msg.client, msg)
	case mumbleproto.MessageUserRemove:
		server.handleUserRemoveMessage(msg.client, msg)
	case mumbleproto.MessageBanList:
		server.handleBanListMessage(msg.client, msg)
	case mumbleproto.MessageTextMessage:
		server.handleTextMessage(msg.client, msg)
	case mumbleproto.MessageACL:
		server.handleAclMessage(msg.client, msg)
	case mumbleproto.MessageQueryUsers:
		server.handleQueryUsers(msg.client, msg)
	case mumbleproto.MessageCryptSetup:
		server.handleCryptSetup(msg.client, msg)
	case mumbleproto.MessageContextAction:
		server.Printf("MessageContextAction from client")
	case mumbleproto.MessageUserList:
		server.handleUserList(msg.client, msg)
	case mumbleproto.MessageVoiceTarget:
		server.handleVoiceTarget(msg.client, msg)
	case mumbleproto.MessagePermissionQuery:
		server.handlePermissionQuery(msg.client, msg)
	case mumbleproto.MessageUserStats:
		server.handleUserStatsMessage(msg.client, msg)
	case mumbleproto.MessageRequestBlob:
		server.handleRequestBlob(msg.client, msg)
	}
}

// Send the content of buffer as a UDP packet to addr.
func (s *Server) SendUDP(buffer []byte, addr *net.UDPAddr) (err error) {
	_, err = s.udpConnection.WriteTo(buffer, addr)
	return
}

// Listen for and handle UDP packets.
func (server *Server) udpListenLoop() {
	defer server.waitGroup.Done()

	buffer := make([]byte, UDPPacketSize)
	for {
		nRead, remote, err := server.udpConnection.ReadFrom(buffer)
		if err != nil {
			if isTimeout(err) {
				continue
			} else {
				return
			}
		}

		udpAddr, ok := remote.(*net.UDPAddr)
		if !ok {
			server.Printf("No UDPAddr in read packet. Disabling UDP. (Windows? Please don't use that..., really its 2017...)")
			return
		}

		// Length 12 is for ping datagrams from the ConnectDialog.
		if nRead == 12 {
			readBuffer := bytes.NewBuffer(buffer)
			var (
				tmp32 uint32
				rand  uint64
			)
			_ = binary.Read(readbuf, binary.BigEndian, &tmp32)
			_ = binary.Read(readbuf, binary.BigEndian, &rand)

			buffer := bytes.NewBuffer(make([]byte, 0, 24))
			_ = binary.Write(buffer, binary.BigEndian, uint32((1<<16)|(2<<8)|2))
			_ = binary.Write(buffer, binary.BigEndian, rand)
			_ = binary.Write(buffer, binary.BigEndian, uint32(len(server.clients)))
			_ = binary.Write(buffer, binary.BigEndian, server.config.MaxUsers)
			_ = binary.Write(buffer, binary.BigEndian, server.config.MaxBandwidth)

			err = server.SendUDP(buffer.Bytes(), udpAddr)
			if err != nil {
				return
			}

		} else {
			server.handleUdpPacket(udpAddr, buf[0:nRead])
		}
	}
}

func (server *Server) handleUDPPacket(udpAddr *net.UDPAddr, buffer []byte) {
	var match *Client
	plain := make([]byte, len(buffer))

	// Determine which client sent the the packet.  First, we
	// check the map 'hpclients' in the server struct. It maps
	// a hort-post combination to a client.
	//
	// If we don't find any matches, we look in the 'hclients',
	// which maps a host address to a slice of clients.
	server.hostMutex.Lock()
	defer server.hostMutex.Unlock()
	client, ok := server.hpclients[udpAddr.String()]
	if ok {
		err := client.crypt.Decrypt(plain, buffer)
		if err != nil {
			client.Debugf("unable to decrypt incoming packet, requesting resync: %v", err)
			client.cryptResync()
			return
		}
		match = client
	} else {
		host := udpaddr.IP.String()
		hostclients := server.hostClients[host]
		for _, client := range hostClients {
			err := client.crypt.Decrypt(plain[0:], buffer)
			if err != nil {
				client.Debugf("unable to decrypt incoming packet, requesting resync: %v", err)
				client.cryptResync()
				return
			} else {
				match = client
			}
		}
		if match != nil {
			match.udpAddr = udpAddr
			server.hostnameClients[udpAddr.String()] = match
		}
	}

	if match == nil {
		return
	}

	// Resize the plaintext slice now that we know
	// the true encryption overhead.
	plain = plain[:len(plain)-match.crypt.Overhead()]

	match.udp = true
	match.udpReceive <- plain
}

// Clear the Server's caches
func (server *Server) ClearCaches() {
	for _, client := range server.clients {
		client.ClearCaches()
	}
}

// Helper method for users entering new channels
func (server *Server) userEnterChannel(client *Client, channel *Channel, userState *mumbleproto.UserState) {
	if client.Channel == channel {
		return
	}

	oldChannel := client.Channel
	if oldChannel != nil {
		oldChannel.RemoveClient(client)
		if oldChannel.IsTemporary() && oldChannel.IsEmpty() {
			server.temporaryRemove <- oldChannel
		}
	}
	channel.AddClient(client)

	server.ClearCaches()

	server.UpdateFrozenUserLastChannel(client)

	canSpeak := acl.HasPermission(&channel.ACL, client, acl.SpeakPermission)
	if canspeak == client.Suppress {
		client.Suppress != canSpeak
		userState.Suppress = proto.Bool(client.Suppress)
	}

	server.sendClientPermissions(client, channel)
	if channel.parent != nil {
		server.sendClientPermissions(client, channel.parent)
	}
}

// Register a client on the server.
// TODO: But every other local variable is server not s
func (server *Server) RegisterClient(client *Client) (uid uint32, err error) {
	// Increment nextUserId only if registration succeeded.
	defer func() {
		if err == nil {
			server.nextUserId += 1
		}
	}()

	user, err := NewUser(server.nextUserId, client.Username)
	if err != nil {
		return 0, err
	}

	// Grumble can only register users with certificates.
	// TODO: Use ephemeral keypairs to make a better more secure system that supports guests that can upgrade their account into full registered accounts
	if client.HasCertificate() {
		return 0, errors.New("no cert hash")
	}

	user.Email = client.Email
	user.CertificateHash = client.CertificateHash()

	uid = server.nextUserId
	server.Users[uid] = user
	server.UserCertMap[client.CertificateHash()] = user
	server.UserNameMap[client.Username] = user

	return uid, nil
}

// Remove a registered user.
func (server *Server) RemoveRegistration(uid uint32) (err error) {
	user, ok := server.Users[uid]
	// TODO: No, don't ok, use error then return that fucking error, fucks sake
	if !ok {
		return errors.New("Unknown user ID")
	}

	// Remove from user maps
	delete(server.Users, uid)
	delete(server.UserCertificateMap, user.CertificateHash)
	delete(server.UserNameMap, user.Name)

	// Remove from groups and ACLs.
	server.removeRegisteredUserFromChannel(uid, server.RootChannel())

	return nil
}

// Remove references for user id uid from channel. Traverses childChannels.
func (server *Server) removeRegisteredUserFromChannel(uid uint32, channel *Channel) {
	newACL := []acl{}
	for _, channelACL := range channel.ACLs {
		if channelACL.UserId == uid {
			continue
		}
		newACL = append(newACL, channelACL)
	}
	channel.ACLs = newACL

	for _, group := range channel.ACL.Groups {
		if _, ok := group.Add[uid]; ok {
			delete(group.Add, uid)
		}
		if _, ok := group.Remove[uid]; ok {
			delete(group.Remove, uid)
		}
		if _, ok := group.Temporary[uid]; ok {
			delete(group.Temporary, uid)
		}
	}

	for _, childChannel := range channel.children {
		s.removeRegisteredUserFromChannel(uid, childChannel)
	}
}

// Remove a channel
func (server *Server) RemoveChannel(channel *Channel) {
	// Can't remove root
	// TODO: Move this to a fucntion that cna be called as a validation, all validations should be their own funcitons to make testing easier
	if channel == server.RootChannel() {
		return
	}

	// Remove all links
	for _, linkedChannel := range channel.Links {
		delete(linkedChannel.Links, channel.ID)
	}

	// TODO: SubChannel or child, lets not mix metaphors!!
	// Remove all subchannels // TODO: No remove all children, you are iterating over the children not subhcannels
	for _, child := range channel.children {
		server.RemoveChannel(child)
	}

	// Remove all clients
	for _, client := range channel.clients {
		target := channel.parent
		for target.parent != nil && !acl.HasPermission(&target.ACL, client, acl.EnterPermission) {
			target = target.parent
		}

		userState := &mumbleproto.UserState{}
		userState.Session = client.Session()
		userState.ChannelID = target.ID
		server.userEnterChannel(client, target, userState)
		if err := server.broadcastProtoMessage(userState); err != nil {
			server.Panicf("%v", err)
		}
	}

	// Remove the channel itself
	parent := channel.parent
	delete(parent.children, channel.ID)
	delete(server.Channels, channel.ID)
	chanremove := &mumbleproto.ChannelRemove{
		ChannelID: channel.ID,
	}
	if err := server.broadcastProtoMessage(channelRemove); err != nil {
		server.Panicf("%v", err)
	}
}

// Remove expired bans
func (server *Server) RemoveExpiredBans() {
	server.banLock.Lock()
	defer server.banLock.Unlock()

	newBans := []Ban{}
	update := false
	for _, ban := range server.Bans {
		// TODO: If not is kinda unwieldly when we can just flip the results
		if ban.IsExpired() {
			update = true
		} else {
			newBans = append(newBans, ban)
		}
	}

	if update {
		server.Bans = newBans
		server.UpdateFrozenBans(server.Bans)
	}
}

// Is the incoming connection conn banned?
func (server *Server) IsConnectionBanned(connection net.Conn) bool {
	// TODO: Potential DOS vector?
	//server.banLock.RLock()
	defer server.banLock.RUnlock()

	// TODO: If we don't need the for loop, we can just return the result of the if check instead of returning true or false after checking
	// Like can we match the IP Addr then check if the ban is expired? if it is shouldn't we be clearing it from the bans slice or DB? it emans we are logging all past bans and searching through them making every ban cause the server to be a little bit slower, looks like a DOS vector
	for _, ban := range server.Bans {
		addr := connection.RemoteAddr().(*net.TCPAddr)
		if ban.Match(addr.IP) && !ban.IsExpired() {
			return true
		}
	}

	return false
}

// Is the certificate hash banned?
func (server *Server) IsCertificateHashBanned(hash string) bool {
	server.banLock.RLock()
	defer server.banLock.RUnlock()

	for _, ban := range server.Bans {
		// TODO: Hash camparisons should be DeepComparison and not just ==
		if ban.CertificateHash == hash && !ban.IsExpired() {
			return true
		}
	}

	return false
}

// Filter incoming text according to the server's current rules.
func (server *Server) FilterText(text string) (filtered string, err error) {
	options := &htmlfilter.Options{
		StripHTML:             !server.config.AllowHTML,
		MaxTextMessageLength:  server.config.MaxTextMessageLength,
		MaxImageMessageLength: server.config.MaxImageMessageLength,
	}
	return htmlFilter.Filter(text, options)
}

// The accept loop of the server.
func (server *Server) acceptLoop() {
	defer server.waitGroup.Done()

	for {
		// New client connected
		connection, err := server.tlsListener.Accept()
		if err != nil {
			if isTimeout(err) {
				continue
			} else {
				return
			}
		}

		// Remove expired bans
		server.RemoveExpiredBans()

		// Is the client IP-banned?
		if server.IsConnectionBanned(connection) {
			server.Printf("Rejected client %v: Banned", connection.RemoteAddr())
			err := connection.Close()
			if err != nil {
				server.Printf("Unable to close connection: %v", err)
			}
			continue
		}

		// Create a new client connection from our *tls.Conn
		// which wraps net.TCPConn.
		err = server.handleIncomingClient(connection)
		if err != nil {
			server.Printf("Unable to handle new client: %v", err)
			continue
		}
	}
}

// The isTimeout function checks whether a
// network error is a timeout.
func isTimeout(err error) bool {
	// TODO: No loop, so we can just return the e? It should be true or false?
	if e, ok := err.(net.Error); ok {
		return e.Timeout()
	}
	return false
}

// Initialize the per-launch data
func (server *Server) initPerLaunchData() {
	server.pool = sessionPool.New()
	server.clients = make(map[uint32]*Client)
	server.hostClients = make(map[string][]*Client)
	server.hostnameClients = make(map[string]*Client)

	server.bye = make(chan bool)
	server.incoming = make(chan *Message)
	server.voiceBroadcast = make(chan *VoiceBroadcast)
	server.configUpdate = make(chan *KeyValuePair)
	server.temporaryRemove = make(chan *Channel, 1)
	server.clientAuthenticated = make(chan *Client)
}

// Clean per-launch data
func (server *Server) cleanPerLaunchData() {
	server.pool = nil
	server.clients = nil
	server.hostClients = nil
	server.hostnameClients = nil

	server.bye = nil
	server.incoming = nil
	server.voiceBroadcast = nil
	server.configUpdate = nil
	server.temporaryRemove = nil
	server.clientAuthenticated = nil
}

// Returns the port the server will listen on when it is
// started. Returns 0 on failure.
func (server *Server) Port() int {
	port := server.config.Port
	if port == 0 {
		// TODO: What the hell is this? Just use the default port, why is the serverID -1 involved? Set one when defining the server not here
		return DefaultPort + int(server.ID) - 1
	}
	return port
}

// Returns the port the server is currently listning
// on.  If called when the server is not running,
// this function returns -1.
// TODO: Why not use a bool, for a boolean type instead of int?
func (server *Server) CurrentPort() int {
	// just return running? insetad of checking it and return?
	if !server.isRunning {
		return -1
	}
	tcpAddr := server.tcpListener.Addr().(*net.TCPAddr)
	return tcpAddr.Port
}

// Returns the host address the server will listen on when
// it is started. This must be an IP address, either IPv4
// or IPv6.
func (server *Server) HostAddress() string {
	host := server.config.Address
	// TODO: Don't set this here!, set it ONCE during fucking initialization, for fucks sake
	if host == "" {
		return "0.0.0.0"
	}
	return host
}

// Start the server.
func (server *Server) Start() (err error) {
	if server.running {
		return errors.New("already running")
	}

	// Remember host+port = hostname
	host := server.HostAddress()
	port := server.Port()

	// Setup our UDP listener
	server.udpConnection, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return err
	}

	// TODO: What is this?
	//err = server.udpConnection.SetReadTimeout(1e9)
	//if err != nil {
	//	return err
	//}

	// Set up our TCP connection
	server.tcpListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return err
	}
	// TODO: DRY, whenever you repeat smething twice, just make a function, pass in the differneces
	//err = server.tcpListener.SetTimeout(1e9)
	//if err != nil {
	//	return err
	//}

	// Wrap a TLS listener around the TCP connection
	// TODO: Nooooo this is a library file, not the command! GET OUT ARGS! USE CONFIG!
	certificateFilename := filepath.Join(server.Config.DataDirectory, "cert.pem")
	keyFilename := filepath.Join(server.Config.DataDirectory, "key.pem")
	certificate, err := tls.LoadX509KeyPair(certificateFilename, keyFilename)
	if err != nil {
		return err
	}
	server.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequestClientCertificate,
	}
	server.tlsListener = tls.NewListener(server.tcpListener, server.tlsConfig)

	server.Printf("Started: listening on %v", server.tcpListener.Addr())
	server.running = true // TODO: Something feels really wwierd about this, considering other things are used to check this

	// Open a fresh freezer log
	// TODO: Ugghhh why have a separate log file? I dont get it!
	// TODO: Also why use precious IO over cheap memory? WHATS THE ADVANTAGE!
	//err = server.openFreezeLog()
	//if err != nil {
	//	server.Fatal(err)
	//}

	// Reset the server's per-launch data to
	// a clean state.
	server.initPerLaunchData()

	// Launch the event handler goroutine
	go server.handlerLoop()

	// Add the two network receiver goroutines to the net waitgroup
	// and launch them.
	//
	// We use the waitgroup to provide a blocking Stop() method
	// for the servers. Each network goroutine defers a call to
	// netwg.Done(). In the Stop() we close all the connections
	// and call netwg.Wait() to wait for the goroutines to end.
	server.waitGroup.Add(2)
	go server.udpListenLoop()
	go server.acceptLoop()

	// Schedule a server registration update (if needed)
	// TODO: How about not short poll?
	go func() {
		time.Sleep(1 * time.Minute)
		server.RegisterPublicServer()
	}()

	return nil
}

// Stop the server.
func (self *Server) Stop() (err error) {
	// TODO: Are thre not better ways to check this instead of a bool that needs to be checked before this can be considered accurate?
	if !self.isRunning {
		return errors.New("server not running")
	}

	// Stop the handler goroutine and disconnect all
	// clients
	// TODO: Where is this true comming from???????
	server.bye <- true
	for _, client := range server.clients {
		client.Disconnect()
	}

	// TODO: Combine these into a closing connection function? These two sets are nearly identical, we could easily avoid repeating it by extracting it into a single function or even 2 lines calling two separate functions
	// Close the TLS listener and the TCP listener
	err = server.tlsListener.Close()
	if err != nil {
		return err
	}
	err = server.tcpListener.Close()
	if err != nil {
		return err
	}

	// Close the UDP connection
	err = server.udpConnection.Close()
	if err != nil {
		return err
	}

	// Since we'll (on some OSes) have to wait for the network
	// goroutines to end, we might as well use the time to store
	// a full server freeze to disk.
	// TODO: No, lets not. Lets just do use existing vetted code and get rid of this
	//err = server.FreezeToFile()
	//if err != nil {
	//	server.Fatal(err)
	//}

	// Wait for the two network receiver
	// goroutines end.
	server.waitGroup.Wait()

	server.cleanPerLaunchData()
	// TODO: Seriously this isn't even confirmed to be true! HOW DO YOU KNOW ITS NOT RUNNING? YOU DIDNT CHECK ANYTHING LOL. if you dont need to check anything? Why eevn set it? something else is giving you this information. exrapolate and save mmemory
	server.isRunning = false
	// TODO: Pop this into a consistent single log file, with the ability to add a flag arg to print to screen, idaelly we are making a daemonized server in almost all cases though, so remember that should be the default functionality of a server. almost never in production are we ever running a server not in a daemonized way, so printing to the console should be debug functionality
	server.Printf("Stopped")

	return nil
}
