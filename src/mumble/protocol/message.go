package protocol

import (
	"crypto/aes"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/golang/protobuf/proto"

	"mumble/protocol/mumbleproto"
)

//TODO: IF YOU ARE WORKING ON A FUCKING 1K+ LINE FILE. STOP AND BREAK THAT SHIT UP, good place to start? Look at your variety of structs, those can each be isolated into thier own file so all the functions in that file relate to that fucking struct. Its like a model in rails, and it makes code actually manageable by other developers and saves EVERYONE time and lets us contribute in meaningful ways without wasting anyones time
type Message struct {
	buffer []byte
	kind   uint16
	client *Client
}

// TODO: Is this better in Client or Voice/Broadcast module within this package?
type VoiceBroadcast struct {
	// The client who is performing the broadcast
	client *Client
	// The VoiceTarget identifier.
	target byte
	// The voice packet itself.
	buffer []byte
}

func (server *Server) handleCryptSetup(client *Client, message *Message) {
	cryptSetup := &mumbleproto.CryptSetup{}
	err := proto.Unmarshal(message.buffer, cryptSetup)
	if err != nil {
		client.Panic(err)
		return
	}

	// No client nonce. This means the client
	// is requesting that we re-sync our nonces.
	// TODO: checking empty by counting more than 0/1? Waste of cpu
	if len(cryptSetup.ClientNonce) == 0 {
		client.Printf("Requested crypt-nonce resync")
		cryptSetup.ClientNonce = make([]byte, aes.BlockSize)
		if copy(cryptSetup.ClientNonce, client.crypt.EncryptIV[0:]) != aes.BlockSize {
			return
		}
		client.sendMessage(cryptSetup)
	} else {
		client.Printf("Received client nonce")
		// TODO: checking empty by counting more than 0/1? Waste of cpu
		if len(cryptSetup.ClientNonce) != aes.BlockSize {
			return
		}

		client.crypt.Resync += 1
		if copy(client.crypt.DecryptIV[0:], cryptSetup.ClientNonce) != aes.BlockSize {
			return
		}
		client.Printf("Crypt re-sync successful")
	}
}

// TODO: Not very DRY, lots of room for improvement ehre
func (server *Server) handlePingMessage(client *Client, message *Message) {
	ping := &mumbleproto.Ping{}
	err := proto.Unmarshal(message.buffer, ping)
	if err != nil {
		client.Panic(err)
		return
	}

	if ping.Good != nil {
		client.crypt.RemoteGood = uint32(*ping.Good)
	}
	if ping.Late != nil {
		client.crypt.RemoteLate = *ping.Late
	}
	if ping.Lost != nil {
		client.crypt.RemoteLost = *ping.Lost
	}
	if ping.Resync != nil {
		client.crypt.RemoteResync = *ping.Resync
	}

	if ping.UdpPingAvg != nil {
		client.UdpPingAvg = *ping.UdpPingAvg
	}
	if ping.UdpPingVar != nil {
		client.UdpPingVar = *ping.UdpPingVar
	}
	if ping.UdpPackets != nil {
		client.UdpPackets = *ping.UdpPackets
	}

	if ping.TcpPingAvg != nil {
		client.TcpPingAvg = *ping.TcpPingAvg
	}
	if ping.TcpPingVar != nil {
		client.TcpPingVar = *ping.TcpPingVar
	}
	if ping.TcpPackets != nil {
		client.TcpPackets = *ping.TcpPackets
	}

	client.sendMessage(&mumbleproto.Ping{
		Timestamp: ping.Timestamp,
		Good:      proto.Uint32(uint32(client.crypt.Good)),
		Late:      proto.Uint32(uint32(client.crypt.Late)),
		Lost:      proto.Uint32(uint32(client.crypt.Lost)),
		Resync:    proto.Uint32(uint32(client.crypt.Resync)),
	})
}

func (server *Server) handleChannelRemoveMessage(client *Client, message *Message) {
	channelRemove := &mumbleproto.ChannelRemove{}
	err := proto.Unmarshal(message.buffer, channelRemove)
	if err != nil {
		client.Panic(err)
		return
	}

	if channelRemove.ChannelID == nil {
		return
	}

	channel, exists := server.Channels[int(*channelRemove.ChannelID)]
	if !exists {
		return
	}

	//if *(&channel.ACL.HasPermission(client.Context, client, acl.WritePermission)) {
	//	client.sendPermissionDenied(client, channel, acl.WritePermission)
	//	return
	//}

	// Update datastore
	//if !channel.IsTemporary() {
	//	server.DeleteFrozenChannel(channel)
	//}

	server.RemoveChannel(channel)
}

// Handle channel state change.
func (server *Server) handleChannelStateMessage(client *Client, message *Message) {
	channelState := &mumbleproto.ChannelState{}
	err := proto.Unmarshal(message.buffer, channelState)
	if err != nil {
		client.Panic(err)
		return
	}

	// TODO: This feels like it belongs in a struct, not just loose as a local variable...
	var channel *Channel
	var parent *Channel
	var ok bool

	// Lookup channel for channel ID
	if channelState.ChannelID != nil {
		channel, ok = server.Channels[int(*channelState.ChannelID)]
		if !ok {
			client.Panic("Invalid channel specified in ChannelState message")
			return
		}
	}

	// Lookup parent
	if channelState.Parent != nil {
		parent, ok = server.Channels[int(*channelState.Parent)]
		// TODO: Ok should be err, and provide the fucking string, god damn
		if !ok {
			client.Panic("Invalid parent channel specified in ChannelState message")
			return
		}
	}

	// The server can't receive links through the links field in the ChannelState message,
	// because clients are supposed to send modifications to a channel's link state through
	// the links_add and links_remove fields.
	// Make sure the links field is clear so we can transmit the channel's link state in our reply.
	channelState.Links = nil

	// TODO: this cant be right and the function is way too long
	var name string
	var description string

	// Extract the description and perform sanity checks.
	if channelState.Description != nil {
		description, err = server.FilterText(*channelState.Description)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Extract the the name of channel and check whether it's valid.
	// A valid channel name is a name that:
	//  a) Isn't already used by a channel at the same level as the channel itself (that is, channels
	//     that have a common parent can't have the same name.
	//  b) A name must be a valid name on the server (it must pass the channel name regexp)
	if channelState.Name != nil {
		name = *channelState.Name

		// TODO: Why not? and this is a poor way to check and each valdiation should be in its own function
		// We don't allow renames for the root channel.
		if channel != nil && channel.ID != 0 {
			// Pick a parent. If the name change is part of a re-parent (a channel move),
			// we must evaluate the parent variable. Since we're explicitly exlcuding the root
			// channel from renames, channels that are the target of renames are guaranteed to have
			// a parent.
			channelParent := parent
			// TODO: Really why not just check parent?
			if channelParent == nil {
				channelParent = channel.parent
			}
			for _, childChannel := range channelParent.children {
				// TODO: No, this is not the thing you should be doing...
				if childChannel.Name == name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}
	}

	// If the channel does not exist already, the ChannelState message is a create operation.
	if channel == nil {
		// TODO: Lets not waste CPU counting past 0 when checking lenght of a string yah?
		if parent == nil || len(name) == 0 {
			return
		}

		// TODO: Nope
		// Check whether the client has permission to create the channel in parent.
		//permission := acl.Permission(acl.NonePermission)
		//if *channelState.Temporary {
		//	permission = acl.Permission(acl.TempChannelPermission)
		//} else {
		//	permission = acl.Permission(acl.MakeChannelPermission)
		//}
		//if !acl.HasPermission(&parent.ACL, client, permission) {
		//	client.sendPermissionDenied(client, parent, permission)
		//	return
		//}

		// Only registered users can create channels.
		if !client.IsRegistered() && !client.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, client)
			return
		}

		// We can't add channels to a temporary channel
		if parent.IsTemporary() {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
			return
		}

		key := ""
		if len(description) > 0 {
			key, err = BlobStorePut([]byte(description))
			if err != nil {
				server.Panicf("Blobstore error: %v", err)
			}
		}

		// Add the new channel
		channel = server.AddChannel(name)
		channel.DescriptionBlob = key
		channel.temporary = *chanstate.Temporary
		channel.Position = int(*chanstate.Position)
		parent.AddChild(channel)

		// Add the creator to the channel's admin group
		if client.IsRegistered() {
			grp := acl.EmptyGroupWithName("admin")
			grp.Add[client.UserID()] = true
			channel.ACL.Groups["admin"] = grp
		}

		// If the client wouldn't have WritePermission in the just-created channel,
		// add a +write ACL for the user's hash.
		if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
			aclEntry := acl.ACL{}
			aclEntry.ApplyHere = true
			aclEntry.ApplySubs = true
			if client.IsRegistered() {
				aclEntry.UserID = client.UserID()
			} else {
				aclEntry.Group = "$" + client.CertHash()
			}
			aclEntry.Deny = acl.Permission(acl.NonePermission)
			aclEntry.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

			channel.ACL.ACLs = append(channel.ACL.ACLs, aclEntry)

			server.ClearCaches()
		}

		chanstate.ChannelID = proto.Uint32(channel.ID)

		// Broadcast channel add
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description if client knows how to handle blobs.
		if chanstate.Description != nil && channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})

		// If it's a temporary channel, move the creator in there.
		if channel.IsTemporary() {
			userstate := &mumbleproto.UserState{}
			userstate.Session = proto.Uint32(client.Session())
			userstate.ChannelID = proto.Uint32(channel.ID)
			server.userEnterChannel(client, channel, userstate)
			server.broadcastProtoMessage(userstate)
		}
	} else {
		// Edit existing channel.
		// First, check whether the actor has the neccessary permissions.

		// Name change.
		if chanstate.Name != nil {
			// The client can only rename the channel if it has WritePermission in the channel.
			// Also, clients cannot change the name of the root channel.
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) || channel.ID == 0 {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}
		}

		// Description change
		if chanstate.Description != nil {
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}
		}

		// Position change
		if chanstate.Position != nil {
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}
		}

		// Parent change (channel move)
		if parent != nil {
			// No-op?
			if parent == channel.parent {
				return
			}

			// Make sure that channel we're operating on is not a parent of the new parent.
			iter := parent
			for iter != nil {
				if iter == channel {
					client.Panic("Illegal channel reparent")
					return
				}
				iter = iter.parent
			}

			// A temporary channel must not have any subchannels, so deny it.
			if parent.IsTemporary() {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
				return
			}

			// To move a channel, the user must have WritePermission in the channel
			if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
				client.sendPermissionDenied(client, channel, acl.WritePermission)
				return
			}

			// And the user must also have MakeChannel permission in the new parent
			if !acl.HasPermission(&parent.ACL, client, acl.MakeChannelPermission) {
				client.sendPermissionDenied(client, parent, acl.MakeChannelPermission)
				return
			}

			// If a sibling of parent already has this name, don't allow it.
			for _, iter := range parent.children {
				if iter.Name == channel.Name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}

		// Links
		linkadd := []*Channel{}
		linkremove := []*Channel{}
		if len(chanstate.LinksAdd) > 0 || len(chanstate.LinksRemove) > 0 {
			// Client must have permission to link
			if !acl.HasPermission(&channel.ACL, client, acl.LinkChannelPermission) {
				client.sendPermissionDenied(client, channel, acl.LinkChannelPermission)
				return
			}
			// Add any valid channels to linkremove slice
			for _, cid := range chanstate.LinksRemove {
				if iter, ok := server.Channels[uint32(cid)]; ok {
					linkremove = append(linkremove, iter)
				}
			}
			// Add any valid channels to linkadd slice
			for _, cid := range chanstate.LinksAdd {
				if iter, ok := server.Channels[uint32(cid)]; ok {
					if !acl.HasPermission(&iter.ACL, client, acl.LinkChannelPermission) {
						client.sendPermissionDenied(client, iter, acl.LinkChannelPermission)
						return
					}
					linkadd = append(linkadd, iter)
				}
			}
		}

		// Permission checks done!

		// Channel move
		if parent != nil {
			channel.parent.RemoveChild(channel)
			parent.AddChild(channel)
		}

		// Rename
		if chanstate.Name != nil {
			channel.Name = *chanstate.Name
		}

		// Description change
		if chanstate.Description != nil {
			if len(description) == 0 {
				channel.DescriptionBlob = ""
			} else {
				key, err := blobStore.Put([]byte(description))
				if err != nil {
					server.Panicf("Blobstore error: %v", err)
				}
				channel.DescriptionBlob = key
			}
		}

		// Position change
		if chanstate.Position != nil {
			channel.Position = int(*chanstate.Position)
		}

		// Add links
		for _, iter := range linkadd {
			server.LinkChannels(channel, iter)
		}

		// Remove links
		for _, iter := range linkremove {
			server.UnlinkChannels(channel, iter)
		}

		// Broadcast the update
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description blob when sending to 1.2.2 >= users. Only send the blob hash.
		if channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})
	}

	// Update channel in datastore
	if !channel.IsTemporary() {
		server.UpdateFrozenChannel(channel, chanstate)
	}
}

// Handle a user remove packet. This can either be a client disconnecting, or a
// user kicking or kick-banning another player.
func (server *Server) handleUserRemoveMessage(client *Client, msg *Message) {
	userremove := &mumbleproto.UserRemove{}
	err := proto.Unmarshal(msg.buf, userremove)
	if err != nil {
		client.Panic(err)
		return
	}

	// Get the client to be removed.
	removeClient, ok := server.clients[*userremove.Session]
	if !ok {
		client.Panic("Invalid session in UserRemove message")
		return
	}

	isBan := false
	if userremove.Ban != nil {
		isBan = *userremove.Ban
	}

	// Check client's permissions
	perm := acl.Permission(acl.KickPermission)
	if isBan {
		perm = acl.Permission(acl.BanPermission)
	}
	rootChan := server.RootChannel()
	if removeClient.IsSuperUser() || !acl.HasPermission(&rootChan.ACL, client, perm) {
		client.sendPermissionDenied(client, rootChan, perm)
		return
	}

	if isBan {
		ban := ban.Ban{}
		ban.IP = removeClient.conn.RemoteAddr().(*net.TCPAddr).IP
		ban.Mask = 128
		if userremove.Reason != nil {
			ban.Reason = *userremove.Reason
		}
		ban.Username = removeClient.ShownName()
		ban.CertHash = removeClient.CertHash()
		ban.Start = time.Now().Unix()
		ban.Duration = 0

		server.banlock.Lock()
		server.Bans = append(server.Bans, ban)
		server.UpdateFrozenBans(server.Bans)
		server.banlock.Unlock()
	}

	userremove.Actor = proto.Uint32(client.Session())
	if err = server.broadcastProtoMessage(userremove); err != nil {
		server.Panicf("Unable to broadcast UserRemove message")
		return
	}

	if isBan {
		client.Printf("Kick-banned %v (%v)", removeClient.ShownName(), removeClient.Session())
	} else {
		client.Printf("Kicked %v (%v)", removeClient.ShownName(), removeClient.Session())
	}

	removeClient.ForceDisconnect()
}

// Handle user state changes
func (server *Server) handleUserStateMessage(client *Client, message *Message) {
	userState := &mumbleproto.UserState{}
	err := proto.Unmarshal(message.buffer, userState)
	if err != nil {
		client.Panic(err)
		return
	}

	actor, ok := server.clients[client.Session()]
	if !ok {
		server.Panic("Client not found in server's client map.")
		return
	}
	target := actor
	if userState.Session != nil {
		target, ok = server.clients[*userState.Session]
		if !ok {
			client.Panic("Invalid session in UserState message")
			return
		}
	}

	userState.Session = proto.Uint32(target.Session())
	userState.Actor = proto.Uint32(actor.Session())

	// Does it have a channel ID?
	if userState.ChannelID != nil {
		// Destination channel
		dstChan, ok := server.Channels[uint32(*userState.ChannelID)]
		if !ok {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has MovePermission on
		// the user's curent channel.
		if actor != target && !acl.HasPermission(&target.Channel.ACL, actor, acl.MovePermission) {
			client.sendPermissionDenied(actor, target.Channel, acl.MovePermission)
			return
		}

		// Check whether the actor has MovePermission on dstChan.  Check whether user has EnterPermission
		// on dstChan.
		if !acl.HasPermission(&dstChan.ACL, actor, acl.MovePermission) && !acl.HasPermission(&dstChan.ACL, target, acl.EnterPermission) {
			client.sendPermissionDenied(target, dstChan, acl.EnterPermission)
			return
		}

		// TODO: Since its already in the server config, no need for local variable
		maxChannelUsers := server.config.MaxChannelUsers
		if maxChannelUsers != 0 && len(dstChan.clients) >= maxChannelUsers {
			client.sendPermissionDeniedFallback(mumbleproto.PermissionDenied_ChannelFull,
				0x010201, "Channel is full")
			return
		}
	}

	if userState.Mute != nil || userState.Deaf != nil || userState.Suppress != nil || userState.PrioritySpeaker != nil {
		// Disallow for SuperUser
		if target.IsSuperUser() {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_SuperUser)
			return
		}

		// Check whether the actor has 'mutedeafen' permission on user's channel.
		if !acl.HasPermission(&target.Channel.ACL, actor, acl.MuteDeafenPermission) {
			client.sendPermissionDenied(actor, target.Channel, acl.MuteDeafenPermission)
			return
		}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userState.Suppress != nil {
			client.sendPermissionDenied(actor, target.Channel, acl.MuteDeafenPermission)
			return
		}
	}

	// Comment set/clear
	if userState.Comment != nil {
		comment := *userState.Comment

		// Clearing another user's comment.
		if target != actor {
			// Check if actor has 'move' permissions on the root channel. It is needed
			// to clear another user's comment.
			rootChan := server.RootChannel()
			if !acl.HasPermission(&rootChan.ACL, actor, acl.MovePermission) {
				client.sendPermissionDenied(actor, rootChan, acl.MovePermission)
				return
			}

			// Only allow empty text.
			if len(comment) > 0 {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
				return
			}
		}

		filtered, err := server.FilterText(comment)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}

		userState.Comment = proto.String(filtered)
	}

	// Texture change
	if userState.Texture != nil {
		// TODO: Since its already in the config, no need for local variable
		maxImageLength := server.config.MaxImageMessageLength
		if maxImageLength > 0 && len(userState.Texture) > maxImageLength {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Registration
	if userState.UserID != nil {
		// If user == actor, check for SelfRegisterPermission on root channel.
		// If user != actor, check for RegisterPermission permission on root channel.
		perm := acl.Permission(acl.RegisterPermission)
		if actor == target {
			perm = acl.Permission(acl.SelfRegisterPermission)
		}

		rootChan := server.RootChannel()
		if target.IsRegistered() || !acl.HasPermission(&rootChan.ACL, actor, perm) {
			client.sendPermissionDenied(actor, rootChan, perm)
			return
		}

		if !target.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, target)
			return
		}
	}

	// Prevent self-targetting state changes to be applied to other users
	// That is, if actor != user, then:
	//   Discard message if it has any of the following things set:
	//      - SelfDeaf
	//      - SelfMute
	//      - Texture
	//      - PluginContext
	//      - PluginIdentity
	//      - Recording
	if actor != target && (userState.SelfDeaf != nil || userState.SelfMute != nil ||
		userstate.Texture != nil || userstate.PluginContext != nil || userstate.PluginIdentity != nil ||
		userstate.Recording != nil) {
		client.Panic("Invalid UserState")
		return
	}

	broadcast := false

	if userstate.Texture != nil && target.user != nil {
		key, err := blobStore.Put(userstate.Texture)
		if err != nil {
			server.Panicf("Blobstore error: %v", err)
			return
		}

		if target.user.TextureBlob != key {
			target.user.TextureBlob = key
		} else {
			userstate.Texture = nil
		}

		broadcast = true
	}

	if userstate.SelfDeaf != nil {
		target.SelfDeaf = *userstate.SelfDeaf
		if target.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
			target.SelfMute = true
		}
		broadcast = true
	}

	if userstate.SelfMute != nil {
		target.SelfMute = *userstate.SelfMute
		if !target.SelfMute {
			userstate.SelfDeaf = proto.Bool(false)
			target.SelfDeaf = false
		}
	}

	if userstate.PluginContext != nil {
		target.PluginContext = userstate.PluginContext
	}

	if userstate.PluginIdentity != nil {
		target.PluginIdentity = *userstate.PluginIdentity
	}

	if userstate.Comment != nil && target.user != nil {
		key, err := blobStore.Put([]byte(*userstate.Comment))
		if err != nil {
			server.Panicf("Blobstore error: %v", err)
		}

		if target.user.CommentBlob != key {
			target.user.CommentBlob = key
		} else {
			userstate.Comment = nil
		}

		broadcast = true
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		if userstate.Deaf != nil {
			target.Deaf = *userstate.Deaf
			if target.Deaf {
				userstate.Mute = proto.Bool(true)
			}
		}
		if userstate.Mute != nil {
			target.Mute = *userstate.Mute
			if !target.Mute {
				userstate.Deaf = proto.Bool(false)
				target.Deaf = false
			}
		}
		if userstate.Suppress != nil {
			target.Suppress = *userstate.Suppress
		}
		if userstate.PrioritySpeaker != nil {
			target.PrioritySpeaker = *userstate.PrioritySpeaker
		}
		broadcast = true
	}

	if userstate.Recording != nil && *userstate.Recording != target.Recording {
		target.Recording = *userstate.Recording

		txtmsg := &mumbleproto.TextMessage{}
		txtmsg.TreeId = append(txtmsg.TreeId, uint32(0))
		if target.Recording {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' started recording", target.ShownName()))
		} else {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' stopped recording", target.ShownName()))
		}

		server.broadcastProtoMessageWithPredicate(txtmsg, func(client *Client) bool {
			return client.Version < 0x10203
		})

		broadcast = true
	}

	userRegistrationChanged := false
	if userstate.UserId != nil {
		uid, err := server.RegisterClient(target)
		if err != nil {
			client.Printf("Unable to register: %v", err)
			userstate.UserId = nil
		} else {
			userstate.UserId = proto.Uint32(uid)
			client.user = server.Users[uid]
			userRegistrationChanged = true
		}
		broadcast = true
	}

	if userstate.ChannelId != nil {
		channel, ok := server.Channels[int(*userstate.ChannelId)]
		if ok {
			server.userEnterChannel(target, channel, userstate)
			broadcast = true
		}
	}

	if broadcast {
		// This variable denotes the length of a zlib-encoded "old-style" texture.
		// Mumble and Murmur used qCompress and qUncompress from Qt to compress
		// textures that were sent over the wire. We can use this to determine
		// whether a texture is a "new style" or an "old style" texture.
		texture := userstate.Texture
		texlen := uint32(0)
		if texture != nil && len(texture) > 4 {
			texlen = uint32(texture[0])<<24 | uint32(texture[1])<<16 | uint32(texture[2])<<8 | uint32(texture[3])
		}
		if texture != nil && len(texture) > 4 && texlen != 600*60*4 {
			// The sent texture is a new-style texture.  Strip it from the message
			// we send to pre-1.2.2 clients.
			userstate.Texture = nil
			err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic("Unable to broadcast UserState")
			}
			// Re-add it to the message, so that 1.2.2+ clients *do* get the new-style texture.
			userstate.Texture = texture
		} else {
			// Old style texture.  We can send the message as-is.
			err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic("Unable to broadcast UserState")
			}
		}

		// If a texture hash is set on user, we transmit that instead of
		// the texture itself. This allows the client to intelligently fetch
		// the blobs that it does not already have in its local storage.
		if userstate.Texture != nil && target.user != nil && target.user.HasTexture() {
			userstate.Texture = nil
			userstate.TextureHash = target.user.TextureBlobHashBytes()
		} else if target.user == nil {
			userstate.Texture = nil
			userstate.TextureHash = nil
		}

		// Ditto for comments.
		if userstate.Comment != nil && target.user.HasComment() {
			userstate.Comment = nil
			userstate.CommentHash = target.user.CommentBlobHashBytes()
		} else if target.user == nil {
			userstate.Comment = nil
			userstate.CommentHash = nil
		}

		if userRegistrationChanged {
			server.ClearCaches()
		}

		err := server.broadcastProtoMessageWithPredicate(userstate, func(client *Client) bool {
			return client.Version >= 0x10203
		})
		if err != nil {
			server.Panic("Unable to broadcast UserState")
		}
	}

	if target.IsRegistered() {
		server.UpdateFrozenUser(target, userstate)
	}
}

func (server *Server) handleBanListMessage(client *Client, message *Message) {
	banlist := &mumbleproto.BanList{}
	err := proto.Unmarshal(message.buffer, banlist)
	if err != nil {
		client.Panic(err)
		return
	}

	rootChan := server.RootChannel()
	if !acl.HasPermission(&rootChan.ACL, client, acl.BanPermission) {
		client.sendPermissionDenied(client, rootChan, acl.BanPermission)
		return
	}

	if banlist.Query != nil && *banlist.Query != false {
		banlist.Reset()

		server.banlock.RLock()
		defer server.banlock.RUnlock()

		for _, ban := range server.Bans {
			entry := &mumbleproto.BanList_BanEntry{}
			entry.Address = ban.IP
			entry.Mask = proto.Uint32(uint32(ban.Mask))
			entry.Name = proto.String(ban.Username)
			entry.Hash = proto.String(ban.CertHash)
			entry.Reason = proto.String(ban.Reason)
			entry.Start = proto.String(ban.ISOStartDate())
			entry.Duration = proto.Uint32(ban.Duration)
			banlist.Bans = append(banlist.Bans, entry)
		}
		if err := client.sendMessage(banlist); err != nil {
			client.Panic("Unable to send BanList")
		}
	} else {
		server.banlock.Lock()
		defer server.banlock.Unlock()

		server.Bans = server.Bans[0:0]
		for _, entry := range banlist.Bans {
			ban := ban.Ban{}
			ban.IP = entry.Address
			ban.Mask = int(*entry.Mask)
			if entry.Name != nil {
				ban.Username = *entry.Name
			}
			if entry.Hash != nil {
				ban.CertHash = *entry.Hash
			}
			if entry.Reason != nil {
				ban.Reason = *entry.Reason
			}
			if entry.Start != nil {
				ban.SetISOStartDate(*entry.Start)
			}
			if entry.Duration != nil {
				ban.Duration = *entry.Duration
			}
			server.Bans = append(server.Bans, ban)
		}

		server.UpdateFrozenBans(server.Bans)

		client.Printf("Banlist updated")
	}
}

// Broadcast text messages
func (server *Server) handleTextMessage(client *Client, message *Message) {
	txtmsg := &mumbleproto.TextMessage{}
	err := proto.Unmarshal(message.buffer, textMessage)
	if err != nil {
		client.Panic(err)
		return
	}

	filtered, err := server.FilterText(*txtmsg.Message)
	if err != nil {
		client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
		return
	}

	if len(filtered) == 0 {
		return
	}

	txtmsg.Message = proto.String(filtered)

	clients := make(map[uint32]*Client)

	// Tree
	for _, chanid := range txtmsg.TreeId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !acl.HasPermission(&channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, channel, acl.TextMessagePermission)
				return
			}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-channel
	for _, chanid := range txtmsg.ChannelId {
		if channel, ok := server.Channels[int(chanid)]; ok {
			if !acl.HasPermission(&channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, channel, acl.TextMessagePermission)
				return
			}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-clients
	for _, session := range txtmsg.Session {
		if target, ok := server.clients[session]; ok {
			if !acl.HasPermission(&target.Channel.ACL, client, acl.TextMessagePermission) {
				client.sendPermissionDenied(client, target.Channel, acl.TextMessagePermission)
				return
			}
			clients[session] = target
		}
	}

	// Remove ourselves
	delete(clients, client.Session())

	for _, target := range clients {
		target.sendMessage(&mumbleproto.TextMessage{
			Actor:   proto.Uint32(client.Session()),
			Message: txtmsg.Message,
		})
	}
}

// ACL set/query
func (server *Server) handleAclMessage(client *Client, message *Message) {
	acl := &mumbleproto.ACL{}
	err := proto.Unmarshal(message.buffer, acl)
	if err != nil {
		client.Panic(err)
		return
	}

	// Look up the channel this ACL message operates on.
	channel, ok := server.Channels[int(*acl.ChannelID)]
	// TODO: return errors, so you can display them! This ok shit is not ok
	if !ok {
		return
	}

	// Does the user have permission to update or look at ACLs?
	if !acl.HasPermission(&channel.acl, client, acl.WritePermission) && !(channel.parent != nil && acl.HasPermission(&channel.parent.acl, client, acl.WritePermission)) {
		client.sendPermissionDenied(client, channel, acl.WritePermission)
		return
	}

	reply := &mumbleproto.ACL{}
	reply.ChannelId = channel.ID

	channels := []*Channel{}
	users := map[int]bool{}

	// Query the current ACL state for the channel
	if acl.Query != nil && *acl.Query != false {
		reply.InheritAcls = proto.Bool(channel.ACL.InheritACL)
		// Walk the channel tree to get all relevant channels.
		// (Stop if we reach a channel that doesn't have the InheritACL flag set)
		// TODO: no, thats not necessary
		cacheChannel := channel
		for cacheChannel != nil {
			channels = append([]*Channel{cacheChannel}, channels...)
			if cacheChannel == channel || cacheChannel.ACL.InheritACL {
				// TODO: Doesn't seem right either
				cacheChannel = cacheChannel.parent
			} else {
				// TODO: Can't be right
				cacheChannel = nil
			}
		}

		// Construct the protobuf ChanACL objects corresponding to the ACLs defined
		// in our channel list.
		reply.Acls = []*mumbleproto.ACL_ChanACL{}
		// TODO: just use proper storage, it will make the code smaller, eaiser to manage
		// Logic that does a specific task? Make it a function, it will make testing actually possible
		for _, channel := range channels {
			for _, childChannel := range channel.ACL.ACLs {
				if childChannel == channel || childChannel.ApplySubs {
					channelACL := &mumbleproto.ACL_ChanACL{}
					// TODO: lol no
					channelACL.Inherited = proto.Bool(channel != channel)
					channelACL.ApplyHere = proto.Bool(childChannel.ApplyHere)
					channelACL.ApplySubs = proto.Bool(childChannel.ApplySubs)
					if childChannel.UserID >= 0 {
						channelACL.UserID = childChannel.UserID
						users[childChannel.UserID] = true
					} else {
						channelACL.Group = proto.String(childChannel.Group)
					}
					channelACL.Grant = proto.Uint32(uint32(childChannel.Allow))
					channelACL.Deny = proto.Uint32(uint32(childChannel.Deny))
					reply.ACLs = append(reply.ACLs, channelACL)
				}
			}
		}

		parent := channel.parent
		allGroupNames := channel.ACL.GroupNames()

		// TODO: This file makes me want to quit programming, its makes me sad.

		// Construct the protobuf ChanGroups that we send back to the client.
		// Also constructs a usermap that is a set user ids from the channel's groups.
		reply.Groups = []*mumbleproto.ACL_ChanGroup{}
		for _, groupName := range allGroupNames {
			// TODO: FIX THIS!
			// Initializing all of these varialbles EVERYTIME through this god damn loop!
			var (
				group          acl.Group
				parentGroup    acl.Group
				hasGroup       bool
				hasParentGroup bool
			)

			group, hasGroup = channel.ACL.Groups[groupName]
			if parent != nil {
				parentGroup, hasParentGroup = parent.ACL.Groups[groupName]
			}

			protocolGroup := &mumbleproto.ACL_ChanGroup{}
			protocolGroup.Name = proto.String(groupName)

			protocolGroup.Inherit = proto.Bool(true)
			if hasGroup {
				protocolGroup.Inherit = proto.Bool(group.Inherit)
			}

			protocolGroup.Inheritable = proto.Bool(true)
			if hasGroup {
				protocolGroup.Inheritable = proto.Bool(group.Inheritable)
			}

			protocolGroup.Inherited = proto.Bool(hasParentGroup && parentGroup.Inheritable)

			// Add the set of user ids that this group affects to the user map.
			// This is used later on in this function to send the client a QueryUsers
			// message that maps user ids to usernames.
			if hasGroup {
				members := map[int]bool{}
				for uid, _ := range group.Add {
					users[uid] = true
					members[uid] = true
				}
				for uid, _ := range group.Remove {
					users[uid] = true
					delete(members, uid)
				}
				for uid, _ := range members {
					// TODO: This should already be a fucking uint32, if you are converting on every comparison you are doing something wrong, rethink your data types
					protocolGroup.Add = append(protocolGroup.Add, uint32(uid))
				}
			}
			if hasParentGroup {
				for uid, _ := range parentGroup.MembersInContext(&parent.ACL) {
					users[uid] = true
					protocolGroup.InheritedMembers = append(protocolGroup.InheritedMembers, uint32(uid))
				}
			}

			reply.Groups = append(reply.Groups, protocolGroup)
		}

		if err := client.sendMessage(reply); err != nil {
			client.Panic(err)
			return
		}

		// TODO: EVEN IF YOU WERE GOING TO DO THIS, WHY not do it in a fucking seperate function? this is like 400 lines, there was no way you could ever write tests for this.
		// Map the user ids in the user map to usernames of users.
		queryUsers := &mumbleproto.QueryUsers{}
		for uid, _ := range users {
			user, ok := server.Users[uint32(uid)]
			if !ok {
				client.Printf("Invalid user id in ACL")
				continue
			}
			queryUsers.IDs = append(queryUsers.IDs, uint32(uid))
			queryUsers.Names = append(queryUsers.Names, user.Name)
		}
		if len(queryusers.IDs) > 0 {
			client.sendMessage(queryUsers)
		}
		// Set new groups and ACLs
	} else {
		// Get old temporary members
		oldTemporaryMembers := map[string]map[int]bool{}
		for name, group := range channel.ACL.Groups {
			oldtmp[name] = group.Temporary
		}

		// Clear current ACLs and groups
		channel.ACL.ACLs = []acl.ACL{}
		channel.ACL.Groups = map[string]acl.Group{}

		// TODO: This repeats WAY to much and is unreadable and full of potential issues
		// IT REQUIRES SIMPLIFICATION, for fucks sake, 1200 lines already? 73% fuck!

		// Add the received groups to the channel.
		channel.ACL.InheritACL = *parentACL.InheritACLs
		for _, relatedGroup := range parentACL.Groups {
			channelGroup := acl.EmptyGroupWithName(*relatedGroup.Name)

			channelGroup.Inherit = *relatedGroup.Inherit
			channelGroup.Inheritable = *relatedGroup.Inheritable
			for _, uid := range relatedGroup.Add {
				channelGroup.Add[int(uid)] = true
			}
			for _, uid := range relatedGroup.Remove {
				channelGroup.Remove[int(uid)] = true
			}
			// TODO: Not ok! Use err, have the error hold the message to display, be consistent!
			if temporaryMembers, ok := oldTemporaryMembers[*relatedGroup.Name]; ok {
				channelGroup.Temporary = temporaryMembers
			}

			channel.ACL.Groups[channelGroup.Name] = channelGroup
		}
		// Add the received ACLs to the channel.
		for _, inheritedACL := range parentACL.ACLs {
			channelACL := acl.ACL{}
			// TODO: Stop repeating shit
			channelACL.ApplyHere = *inheritedACL.ApplyHere
			channelACL.ApplySubs = *inheritedACL.ApplySubs
			if pbacl.UserId != nil {
				// TODO: IF this userID is the admin? Why not AdminID
				// TODO: Stop conerting IDs so much!
				channelACL.UserID = int(*inheritedACL.UserID)
			} else {
				channelACL.Group = *inheritedACL.Group
			}
			channelACL.Deny = acl.Permission(*inheritedACL.Deny & acl.AllPermissions)
			channelACL.Allow = acl.Permission(*inheritedACL.Grant & acl.AllPermissions)

			channel.ACL.ACLs = append(channel.ACL.ACLs, channelACL)
		}

		// Clear the Server's caches
		server.ClearCaches()

		// Regular user?
		if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) && client.IsRegistered() || client.HasCertificate() {
			channelACL := acl.ACL{}
			// TODO: Oh come on. This should not be just statically coded like this, 500 lines in
			channelACL.ApplyHere = true
			channelACL.ApplySubs = false
			if client.IsRegistered() {
				chanacl.UserID = client.UserID()
			} else if client.HasCertificate() {
				channelACL.Group = "$" + client.CertificateHash()
			}
			channelACL.Deny = acl.Permission(acl.NonePermission)
			channelACL.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

			channel.ACL.ACLs = append(channel.ACL.ACLs, channelACL)
			// TODO: Replicate this everywhere and shrink all functions, its just too much for anyone to really test, manage, debug, etc. Just wastes time
			server.ClearCaches()
		}

		// Update freezer
		server.UpdateFrozenChannelACLs(channel)
	}
}

// User query
func (server *Server) handleQueryUsers(client *Client, message *Message) {
	query := &mumbleproto.QueryUsers{}
	err := proto.Unmarshal(message.buffer, query)
	if err != nil {
		client.Panic(err)
		return
	}

	server.Printf("in handleQueryUsers")

	reply := &mumbleproto.QueryUsers{}

	for _, id := range query.IDs {
		user, exists := server.Users[id]
		// TODO: No err not exists, use the error because it gives you something to print. BE CONSISTENT!
		if exists {
			reply.IDs = append(reply.IDs, id)
			reply.Names = append(reply.Names, user.Name)
		}
	}

	for _, name := range query.Names {
		user, exists := server.UserNameMap[name]
		if exists {
			reply.IDs = append(reply.IDs, user.ID)
			reply.Names = append(reply.Names, name)
		}
	}

	if err := client.sendMessage(reply); err != nil {
		client.Panic(err)
		return
	}
}

// User stats message. Shown in the Mumble client when a
// user right clicks a user and selects 'User Information'.
func (server *Server) handleUserStatsMessage(client *Client, message *Message) {
	stats := &mumbleproto.UserStats{}
	err := proto.Unmarshal(message.buffer, stats)
	if err != nil {
		client.Panic(err)
		return
	}

	// TODO: This is a validation, break it out
	if stats.Session == nil {
		return
	}

	// TODO: no, use errors, this doesnt give any fucking information to the user or admin OR THE DEVELOPERS
	target, exists := server.clients[*stats.Session]
	if !exists {
		return
	}

	// TODO: WhAT? Why are you initailzing this here? This is insane, who would want to track all these extra variables?
	// If a client is requesting a UserStats from itself, serve it the whole deal.
	// TODO: No, but if you did extended := (client == target) brings it down from 4 to 1
	extended := (client == target)
	// Otherwise, only send extended UserStats for people with +register permissions
	// on the root channel.
	rootChannel := server.RootChannel()
	// TODO: Another if not needed. It adds up, its a message function!
	extended = acl.HasPermission(&rootChannel.ACL, client, acl.RegisterPermission)

	// If the client wasn't granted extended permissions, only allow it to query
	// users in channels it can enter.
	if !extended && !acl.HasPermission(&target.Channel.ACL, client, acl.EnterPermission) {
		client.sendPermissionDenied(client, target.Channel, acl.EnterPermission)
		return
	}

	// TODO: Why? whats the advantage here, why are we 600 lines in and initializing new god damn varibales? There is no way you could reliably debug this and provide a secure app
	details := extended
	// TODO: I want to vommit
	local := extended || target.Channel == client.Channel
	// TODO: This is the third extra if?
	details = (stats.StatsOnly != nil && *stats.StatsOnly == true)

	stats.Reset()
	stats.Session = proto.Uint32(target.Session())

	if details {
		if tlsConnection := target.connection.(*tls.Conn); tlsConnection != nil {
			state := tlsConnection.ConnectionState()
			for count := len(state.PeerCertificates) - 1; count >= 0; count-- {
				stats.Certificates = append(stats.Certificates, state.PeerCertificates[count].Raw)
			}
			stats.StrongCertificate = proto.Bool(target.IsVerified())
		}
	}

	// TODO: Why wouldn't this be part of the god damn struct?
	// Look for patterns, and extrapolate!
	if local {
		fromClient := &mumbleproto.UserStats_Stats{}
		fromClient.Good = proto.Uint32(target.crypt.Good)
		fromClient.Late = proto.Uint32(target.crypt.Late)
		fromClient.Lost = proto.Uint32(target.crypt.Lost)
		fromClient.Resync = proto.Uint32(target.crypt.Resync)
		stats.FromClient = fromClient

		fromServer := &mumbleproto.UserStats_Stats{}
		fromServer.Good = proto.Uint32(target.crypt.RemoteGood)
		fromServer.Late = proto.Uint32(target.crypt.RemoteLate)
		fromServer.Lost = proto.Uint32(target.crypt.RemoteLost)
		fromServer.Resync = proto.Uint32(target.crypt.RemoteResync)
		stats.FromServer = fromServer
	}

	stats.UdpPackets = proto.Uint32(target.UdpPackets)
	stats.TcpPackets = proto.Uint32(target.TcpPackets)
	stats.UdpPingAvg = proto.Float32(target.UdpPingAvg)
	stats.UdpPingVar = proto.Float32(target.UdpPingVar)
	stats.TcpPingAvg = proto.Float32(target.TcpPingAvg)
	stats.TcpPingVar = proto.Float32(target.TcpPingVar)

	if details {
		version := &mumbleproto.Version{}
		version.Version = proto.Uint32(target.Version)
		// TODO: Why count more than 0 if we are just checking if its 0. This function eats so much extra resources
		if len(target.ClientName) > 0 {
			version.Release = proto.String(target.ClientName)
		}
		// TODO: Why count more than 0 if we are just checking if its 0. This function eats so much extra resources
		if len(target.OSName) > 0 {
			version.Os = proto.String(target.OSName)
			// TODO: Why count more than 0 if we are just checking if its 0. This function eats so much extra resources
			if len(target.OSVersion) > 0 {
				version.OsVersion = proto.String(target.OSVersion)
			}
		}
		stats.Version = version
		stats.CeltVersions = target.codecs
		stats.Opus = proto.Bool(target.opus)
		stats.Address = target.tcpAddr.IP
	}

	// fixme(mkrautz): we don't do bandwidth tracking yet
	// TODO: If its in a separate function, because this is WAY to fucking long

	if err := client.sendMessage(stats); err != nil {
		client.Panic(err)
		return
	}
}

// Voice target message
// TODO: DO these have to be pointers? Should they be?
func (server *Server) handleVoiceTarget(client *Client, message *Message) {
	voiceTarget := &mumbleproto.VoiceTarget{}
	err := proto.Unmarshal(message.buffer, voiceTarget)
	if err != nil {
		client.Panic(err.Error())
		return
	}

	// TODO: PUT VALIDATIONS IN THEIR OWN FUNCTIONS TO BE ABLE TO TEST THEM
	if voiceTarget.ID == nil {
		return
	}

	id := *voiceTarget.ID
	if id < 1 || id >= 0x1f {
		return
	}

	// TODO: Antoher waste of resources counting over the amount needed 1
	if len(voiceTarget.Targets) == 0 {
		delete(client.voiceTargets, id)
	}

	for _, target := range voiceTarget.Targets {
		newTarget := &VoiceTarget{}
		// TODO: This can't be right
		for _, session := range target.Session {
			newTarget.AddSession(session)
		}
		// TODO: validation? get in your own function
		if target.ChannelID != nil {
			// WHY? Why not a struct even if you did do it
			channelID := *target.ChannelID
			group := ""
			links := false
			childChannels := false
			if target.Group != nil {
				group = *target.Group
			}
			if target.Links != nil {
				links = *target.Links
			}
			if target.Children != nil {
				childChannels = *target.Children
			}
			newTarget.AddChannel(channelID, childChannels, links, group)
		}
		if newTarget.IsEmpty() {
			delete(client.voiceTargets, id)
		} else {
			client.voiceTargets[id] = newTarget
		}
	}
}

// TODO: This file makes me want to cry ;_;
// Permission query
func (server *Server) handlePermissionQuery(client *Client, message *Message) {
	query := &mumbleproto.PermissionQuery{}
	err := proto.Unmarshal(message.buffer, query)
	if err != nil {
		client.Panic(err)
		return
	}

	// TODO: This validation exists at least 2 other times. DONT REPEAT - MAKE FUNCS
	if query.ChannelID == nil {
		return
	}

	channel := server.Channels[int(*query.ChannelID)]
	server.sendClientPermissions(client, channel)
}

// Request big blobs from the server
func (server *Server) handleRequestBlob(client *Client, message *Message) {
	requestBlob := &mumbleproto.RequestBlob{}
	err := proto.Unmarshal(message.buffer, requestBlob)
	if err != nil {
		client.Panic(err)
		return
	}

	userState := &mumbleproto.UserState{}

	// Request for user textures
	// TODO: Why count if you only want to know 1 count?
	if len(requestBlob.SessionTexture) > 0 {
		for _, sid := range requestBlob.SessionTexture {
			if target, ok := server.clients[sid]; ok {
				// TODO: NOT OK, use errors, don't leave everyone including yourself in the fucking dark
				// TODO: No, and its a validation!!!!!
				if target.user == nil {
					continue
				}
				if target.user.HasTexture() {
					buffer, err := blobStore.Get(target.user.TextureBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err)
						return
					}
					userState.Reset()
					userState.Session = proto.Uint32(uint32(target.Session()))
					// TODO: What is a texture????? BETTER NAMES
					userState.Texture = buffer
					if err := client.sendMessage(userState); err != nil {
						client.Panic(err)
						return
					}
				}
			}
		}
	}

	// Request for user comments
	// TODO: Stop counting os high!
	if len(requestBlob.SessionComment) > 0 {
		for _, sid := range requestBlob.SessionComment {
			// TODO: Err not ok!
			if target, ok := server.clients[sid]; ok {
				// TODO: REPEATED VALIDATION!!!!!
				if target.user == nil {
					continue
				}
				if target.user.HasComment() {
					buffer, err := BlobStoreGet(target.user.CommentBlob)
					if err != nil {
						// TODO: There is no reason to repeat these fucntions for each class, its just bad
						server.Panicf("Blobstore error: %v", err)
						return
					}
					userState.Reset()
					userState.Session = proto.Uint32(uint32(target.Session()))
					userState.Comment = proto.String(string(buffer))
					if err := client.sendMessage(userState); err != nil {
						client.Panic(err)
						return
					}
				}
			}
		}
	}

	channelState := &mumbleproto.ChannelState{}

	// Request for channel descriptions
	// TODO: Added up, there is SO MUCH WASTE. THESE ARE PER MESSAGE!
	if len(requestBlob.ChannelDescription) > 0 {
		for _, cid := range requestBlob.ChannelDescription {
			if channel, ok := server.Channels[int(cid)]; ok {
				if channel.HasDescription() {
					chanstate.Reset()
					buffer, err := BlobStoreGet(channel.DescriptionBlob)
					if err != nil {
						server.Panicf("Blobstore error: %v", err)
						return
					}
					// TODO: you should be asking yourself, if you are doing a conversion everytime you use a variable, is there something majorly wrong? the answer is yes
					channelState.ChannelID = proto.Uint32(uint32(channel.ID))
					channelState.Description = proto.String(string(buffer))
					if err := client.sendMessage(channelState); err != nil {
						client.Panic(err)
						return
					}
				}
			}
		}
	}
}

// User list query, user rename, user de-register
// TODO: userList and userlist, BE CONSISTENT!
func (server *Server) handleUserList(client *Client, message *Message) {
	userList := &mumbleproto.UserList{}
	err := proto.Unmarshal(message.buffer, userList)
	if err != nil {
		client.Panic(err)
		return
	}

	// Only users who are allowed to register other users can access the user list.
	rootChannel := server.RootChannel()
	if !acl.HasPermission(&rootChannel.ACL, client, acl.RegisterPermission) {
		client.sendPermissionDenied(client, rootChannel, acl.RegisterPermission)
		// TODO: Second time this came up atlest and if you used an error it would be consistent
		return
	}

	// Query user list
	// TODO: STOP COUNTING OVER what youw ant to check!
	if len(userList.Users) == 0 {
		for uid, user := range server.Users {
			// TODO: FUCKING VALIDATION!
			if uid == 0 {
				continue
			}
			// TODO: Isn't server users? why store it in this serpate list that makes it unwieldy and confusing?
			userList.Users = append(userList.Users, &mumbleproto.UserList_User{
				UserID: proto.Uint32(uid),
				Name:   proto.String(user.Name),
			})
		}
		if err := client.sendMessage(userList); err != nil {
			client.Panic(err)
			return
		}
		// Rename, registration removal
	} else {
		// TODO: STOP COUNTING OVER what youw ant to check!
		if len(userList.Users) > 0 {
			tx := server.freezeLog.BeginTx()
			for _, listUser := range userList.Users {
				uid := *listUser.UserID
				// TODO: Repeated validation, make a function!
				if uid == 0 {
					continue
				}
				user, ok := server.Users[uid]
				// TODO NOT OK, ERR! This is useless to everyone
				if ok {
					// TODO: Then validation? serious?
					if listUser.Name == nil {
						// De-register
						server.RemoveRegistration(uid)
						err := tx.Put(&freezer.UserRemove{ID: listUser.UserID})
						// TODO: If you made this a function you could reduce maybe 100 lines per file
						if err != nil {
							server.Fatal(err)
						}
					} else {
						// Rename user
						// todo(mkrautz): Validate name.
						user.Name = *listUser.Name
						err := tx.Put(&freezer.User{ID: listUser.UserID, Name: listUser.Name})
						if err != nil {
							server.Fatal(err)
						}
					}
				}
			}
			err := tx.Commit()
			if err != nil {
				server.Fatal(err)
			}
		}
	}
}
