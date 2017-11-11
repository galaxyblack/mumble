package protocol

import (
	"crypto/aes"
	"crypto/tls"
	"errors"
	"fmt"
	//"net"
	//"time"

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
		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//client.Printf("Requested crypt-nonce resync")
		cryptSetup.ClientNonce = make([]byte, aes.BlockSize)
		if copy(cryptSetup.ClientNonce, client.crypt.EncryptIV[0:]) != aes.BlockSize {
			return
		}
		client.sendMessage(cryptSetup)
	} else {
		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//client.Printf("Received client nonce")
		// TODO: checking empty by counting more than 0/1? Waste of cpu
		if len(cryptSetup.ClientNonce) != aes.BlockSize {
			return
		}

		client.crypt.Resync += 1
		if copy(client.crypt.DecryptIV[0:], cryptSetup.ClientNonce) != aes.BlockSize {
			return
		}
		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//client.Printf("Crypt re-sync successful")
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

	channel, exists := server.Channels[*channelRemove.ChannelID]
	if !exists {
		return
	}

	//if *(&channel.ACL.HasPermission(client.Context, client, WritePermission)) {
	//	client.sendPermissionDenied(client, channel, WritePermission)
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
	// TODO: Don't use ok use error
	var ok bool

	// Lookup channel for channel ID
	if channelState.ChannelID != nil {
		channel, success := server.Channels[*channelState.ChannelID]
		if success {
			client.Panic(errors.New("Invalid channel specified in ChannelState message"))
			return
		}
	}

	// Lookup parent
	if channelState.Parent != nil {
		parent, success := server.Channels[*channelState.Parent]
		// TODO: Ok should be err, and provide the fucking string, god damn
		if success {
			client.Panic(errors.New("Invalid parent channel specified in ChannelState message"))
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
		// TODO you are just checking if its over size of 0 so dont count everything, its a waste
		if len(description) > 0 {
			// TODO: This relies on a blob store existing, and really should just get rid of this code and use a library that maintained instead of reinventing the wheel
			//key, err = BlobStorePut([]byte(description))
			if err != nil {
				server.Panicf("Blobstore error: %v", err)
			}
		}

		// Add the new channel
		channel = server.AddChannel(name)
		channel.DescriptionBlob = key
		channel.temporary = *channelState.Temporary
		channel.Position = *channelState.Position
		parent.AddChild(channel)

		// Add the creator to the channel's admin group
		if client.IsRegistered() {
			// TODO: No this should be in a method of group, adding members should not be implemented inline in message
			//group := NewGroup("admin")
			//group.Add[client.UserID()] = true
			// TODO: Gonna need to correct this
			//channel.ACL.Groups["admin"] = group
		}

		// If the client wouldn't have WritePermission in the just-created channel,
		// add a +write ACL for the user's hash.
		//if !&channel.ACL.HasPermission(client, acl.WritePermission) {
		//	aclEntry := acl.ACL{}
		//	aclEntry.ApplyHere = true
		//	aclEntry.ApplySubs = true
		//	if client.IsRegistered() {
		//		aclEntry.UserID = client.UserID()
		//	} else {
		//		aclEntry.Group = "$" + client.CertificateHash()
		//	}
		//	aclEntry.Deny = acl.Permission(acl.NonePermission)
		//	aclEntry.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

		//	channel.ACL.ACLs = append(channel.ACL.ACLs, aclEntry)

		//	server.ClearCaches()
		//}

		channelState.ChannelID = proto.Uint32(channel.ID)

		// Broadcast channel add
		server.broadcastProtoMessageWithPredicate(channelState, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description if client knows how to handle blobs.
		if channelState.Description != nil && channel.HasDescription() {
			channelState.Description = nil
			channelState.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		server.broadcastProtoMessageWithPredicate(channelState, func(client *Client) bool {
			return client.Version >= 0x10202
		})

		// If it's a temporary channel, move the creator in there.
		if channel.IsTemporary() {
			userState := &mumbleproto.UserState{}
			userState.Session = proto.Uint32(client.Session())
			userState.ChannelID = proto.Uint32(channel.ID)
			server.userEnterChannel(client, channel, userState)
			server.broadcastProtoMessage(userState)
		}
	} else {
		// Edit existing channel.
		// First, check whether the actor has the neccessary permissions.

		// Name change.
		if channelState.Name != nil {
			// The client can only rename the channel if it has WritePermission in the channel.
			// Also, clients cannot change the name of the root channel.
			//if !&channel.ACL.HasPermission(client, acl.WritePermission) || channel.ID == 0 {
			//	client.sendPermissionDenied(client, channel, acl.WritePermission)
			//	return
			//}
		}

		// Description change
		if channelState.Description != nil {
			//if !&channel.ACL.HasPermission(client, acl.WritePermission) {
			//	client.sendPermissionDenied(client, channel, acl.WritePermission)
			//	return
			//}
		}

		// Position change
		if channelState.Position != nil {
			//if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
			//	client.sendPermissionDenied(client, channel, acl.WritePermission)
			//	return
			//}
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
					client.Panic(errors.New("Illegal channel reparent"))
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
			//if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) {
			//	client.sendPermissionDenied(client, channel, acl.WritePermission)
			//	return
			//}

			// And the user must also have MakeChannel permission in the new parent
			//if !acl.HasPermission(&parent.ACL, client, acl.MakeChannelPermission) {
			//	client.sendPermissionDenied(client, parent, acl.MakeChannelPermission)
			//	return
			//}

			// If a sibling of parent already has this name, don't allow it.
			for _, iter := range parent.children {
				if iter.Name == channel.Name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}

		// Links
		// TODO: Why store it in both a struct and and just make variables?
		linksAdded := []*Channel{}
		linksRemoved := []*Channel{}
		// TODO: If we are only checking if at least 1 length why count length over 1 position?
		//if len(channelState.LinksAdded) > 0 || len(channelState.LinksRemoved) > 0 {
		//	// Client must have permission to link
		//	if !acl.HasPermission(&channel.ACL, client, acl.LinkChannelPermission) {
		//		client.sendPermissionDenied(client, channel, acl.LinkChannelPermission)
		//		return
		//	}
		//	// Add any valid channels to linkremove slice
		//	for _, cid := range channelState.LinksRemoved {
		//		if iter, ok := server.Channels[uint32(cid)]; ok {
		//			linksRemoved = append(linksRemoved, iter)
		//		}
		//	}
		//	// Add any valid channels to linkadd slice
		//	for _, cid := range channelState.LinksAdded {
		//		if iter, ok := server.Channels[uint32(cid)]; ok {
		//			if !acl.HasPermission(&iter.ACL, client, acl.LinkChannelPermission) {
		//				client.sendPermissionDenied(client, iter, acl.LinkChannelPermission)
		//				return
		//			}
		//			linksAdded = append(linksAdded, iter)
		//		}
		//	}
		//}

		// Permission checks done!

		// Channel move
		if parent != nil {
			channel.parent.RemoveChild(channel)
			parent.AddChild(channel)
		}

		// Rename
		if channelState.Name != nil {
			channel.Name = *channelState.Name
		}

		// Description change
		if channelState.Description != nil {
			// TODO: This is a validation, so its own fucntion
			// TODO: Checking just if not empty, so dont count every character in description
			if len(description) == 0 {
				channel.DescriptionBlob = ""
			} else {
				// TODO: uhh, no this is fucked
				//key, err := blobStore.Put([]byte(description))
				//if err != nil {
				//	server.Panic(err)
				//}
				//channel.DescriptionBlob = key
			}
		}

		// Position change
		if channelState.Position != nil {
			channel.Position = *channelState.Position
		}

		// Add links
		for _, iter := range linksAdded {
			server.LinkChannels(channel, iter)
		}

		// Remove links
		for _, iter := range linksRemoved {
			server.UnlinkChannels(channel, iter)
		}

		// Broadcast the update
		server.broadcastProtoMessageWithPredicate(channelState, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description blob when sending to 1.2.2 >= users. Only send the blob hash.
		if channel.HasDescription() {
			channelState.Description = nil
			channelState.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		channelState.DescriptionHash = channel.DescriptionBlobHashBytes()
		server.broadcastProtoMessageWithPredicate(channelState, func(client *Client) bool {
			return client.Version >= 0x10202
		})
	}

	// Update channel in datastore
	// TODO: Freezing is dumb, call it writing and use a lib
	//if !channel.IsTemporary() {
	//	server.UpdateFrozenChannel(channel, channelState)
	//}
}

// Handle a user remove packet. This can either be a client disconnecting, or a
// user kicking or kick-banning another player.
// TODO: Appears to be overuse of pointers?
func (server *Server) handleUserRemoveMessage(removedClient *Client, message *Message) {
	usersRemoved := &mumbleproto.UserRemove{}
	err := proto.Unmarshal(message.buffer, usersRemoved)
	if err != nil {
		removedClient.Panic(err)
		return
	}

	// Get the client to be removed.
	// TODO: Do we have the client we are going to remove or not at this point? Im so confused
	removedClientSession := (*removedClient).Session()
	removedClient, ok := server.clients[removedClientSession]
	// TODO: Don't use ok, then use the error to pvodie the message!
	if !ok {
		removedClient.Panic(errors.New("Invalid session in UserRemove message"))
		return
	}
	// Just checked if its banned from the pointer, not a local variable, thats just overcomplex
	// Check client's permissions
	// TODO: Just commenting this out fix it later, this is a bad way anwyay
	//clientPermissions := acl.Permission(acl.KickPermission)
	//if isBanned {
	//	permissionDenied = acl.Permission(acl.BanPermission)
	//}
	// TODO: haspermission needs revamping
	RootChannel := server.RootChannel()
	//if removedClient.IsSuperUser() || !acl.HasPermission(&rootChannel.ACL, removedClient, permissionDenied) {
	//	client.sendPermissionDenied(client, rootChannel, permissionDenied)
	//	return
	//}

	isBanned := false
	// TODO: isBanned handling should be be done not locally but from checking a struct value or db value
	//if isBanned {
	//	ban := ban.Ban{}
	//	ban.IP = removedClient.connection.RemoteAddr().(*net.TCPAddr).IP
	//	ban.Mask = 128
	//	if removedUser.Reason != nil {
	//		ban.Reason = *removedUser.Reason
	//	}
	//	ban.Username = removedClient.ShownName()
	//	ban.CertificateHash = removedClient.CertificateHash()
	//	ban.Start = time.Now().Unix()
	//	ban.Duration = 0

	//	server.banLock.Lock()
	//	server.Bans = append(server.Bans, ban)
	//	server.UpdateFrozenBans(server.Bans)
	//	server.banLock.Unlock()
	//}

	// Actor is just a uint32, whats the point here??
	//removedClient.Actor = proto.Uint32(removedClient.Session())
	if err = server.broadcastProtoMessage(removedClient); err != nil {
		server.Panic(errors.New("Unable to broadcast UserRemove message"))
		return
	}

	if isBanned {
		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//removedClient.Printf("Kick-banned %v (%v)", removedClient.ShownName(), removedClient.Session())
	} else {
		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//removedClient.Printf("Kicked %v (%v)", removedClient.ShownName(), removedClient.Session())
	}

	removedClient.ForceDisconnect()
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
		server.Panic(errors.New("Client not found in server's client map."))
		return
	}
	target := actor
	if userState.Session != nil {
		target, ok = server.clients[*userState.Session]
		if !ok {
			client.Panic(errors.New("Invalid session in UserState message"))
			return
		}
	}

	userState.Session = proto.Uint32(target.Session())
	userState.Actor = proto.Uint32(actor.Session())

	// Does it have a channel ID?
	if userState.ChannelID != nil {
		// Destination channel
		destinationChannel, ok := server.Channels[*userState.ChannelID]
		// TODO: Don't use ok instead of error, errors are created because they provide application state, without that no debugging is possible
		if !ok {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has MovePermission on
		// the user's curent channel.
		// TODO: has permisison sucks
		//if actor != target && !acl.HasPermission(&target.Channel.ACL, actor, acl.MovePermission) {
		//	client.sendPermissionDenied(actor, target.Channel, acl.MovePermission)
		//	return
		//}

		// Check whether the actor has MovePermission on dstChan.  Check whether user has EnterPermission
		// on dstChan.
		// TODO: has permisison sucks
		//if !acl.HasPermission(&dstChan.ACL, actor, acl.MovePermission) && !acl.HasPermission(&destinationChannel.ACL, target, acl.EnterPermission) {
		//	client.sendPermissionDenied(target, destinationChannel, acl.EnterPermission)
		//	return
		//}

		// TODO: Since its already in the server config, no need for local variable
		// TODO: Umm why?
		maxUsersPerChannel := server.config.MaxUsersPerChannel
		// TODO just check if index exists at max value, no need to count every client
		// TODO: Validation != 0
		if maxUsersPerChannel != 0 && destinationChannel.clients[maxUsersPerChannel] != nil {
			client.sendPermissionDeniedFallback(mumbleproto.PermissionDenied_ChannelFull, 0x010201, "Channel is full")
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
		// TODO: has permisison sucks
		//if !HasPermission(&target.Channel.ACL, actor, MuteDeafenPermission) {
		//	client.sendPermissionDenied(actor, target.Channel, MuteDeafenPermission)
		//	return
		//}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userState.Suppress != nil {
			client.sendPermissionDenied(actor, target.Channel, MuteDeafenPermission)
			return
		}
	}

	// Comment set/clear
	if userState.Comment != nil {
		comment := *userState.Comment

		// Clearing another user's comment.
		// TODO: rewrite
		//if target.Session != userState.Actor {
		// Check if actor has 'move' permissions on the root channel. It is needed
		// to clear another user's comment.
		//	rootChannel := server.RootChannel()
		// TODO: has permisison sucks
		//if !acl.HasPermission(&rootChan.ACL, actor, acl.MovePermission) {
		//	client.sendPermissionDenied(actor, rootChannel, acl.MovePermission)
		//	return
		//}

		// Only allow empty text.
		// TODO: Thats find (its a validation and should be in its own function! bu it should also not count the entire coment, just check if the index position is filled
		//	if len(comment) > 0 {
		//		client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
		//		return
		//	}
		//}

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
		// TODO:VALIDATE: not empty length ?? but what is being checked if the configuration value is over 0, wierd, this is why we break this out and validate its functionality with tests
		// TODO:VALIDATE: not over max length
		if maxImageLength > 0 && &(userState.Texture[maxImageLength+1]) != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Registration
	if userState.UserID != nil {
		// If user == actor, check for SelfRegisterPermission on root channel.
		// If user != actor, check for RegisterPermission permission on root channel.
		registeredPermission := Permission(RegisterPermission)
		if actor == target {
			registeredPermission = Permission(SelfRegisterPermission)
		}

		rootChannel := server.RootChannel()
		// TODO: Fix HasPermission
		//if target.IsRegistered() || !&rootChannel.ACL.HasPermission(actor, registeredPermission) {
		//	client.sendPermissionDenied(actor, rootChannel, registeredPermission)
		//	return
		//}

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
		userState.Texture != nil || userState.PluginContext != nil || userState.PluginIdentity != nil ||
		userState.Recording != nil) {
		client.Panic(errors.New("Invalid UserState"))
		return
	}

	broadcast := false

	// TODO: This is gross
	if userState.Texture != nil && target.user != nil {
		// TODO: lets just use a file writing lib
		//key, err := blobStore.Put(userState.Texture)
		//if err != nil {
		//	server.Panic(err)
		//	return
		//}

		// TODO: TextureBlob
		//if target.user.TextureBlob != key {
		//	target.user.TextureBlob = key
		//} else {
		//	userState.Texture = nil
		//}

		broadcast = true
	}

	if userState.SelfDeaf != nil {
		target.SelfDeaf = *userState.SelfDeaf
		if target.SelfDeaf {
			userState.SelfDeaf = proto.Bool(true)
			target.SelfMute = true
		}
		broadcast = true
	}

	if userState.SelfMute != nil {
		target.SelfMute = *userState.SelfMute
		if !target.SelfMute {
			userState.SelfDeaf = proto.Bool(false)
			target.SelfDeaf = false
		}
	}

	if userState.PluginContext != nil {
		target.PluginContext = userState.PluginContext
	}

	if userState.PluginIdentity != nil {
		target.PluginIdentity = *userState.PluginIdentity
	}

	if userState.Comment != nil && target.user != nil {
		// TODO: well replace blboStore anyways
		//key, err := blobStore.Put([]byte(*userState.Comment))
		//if err != nil {
		//	server.Panic(err)
		//}

		//if target.user.CommentBlob != key {
		//	target.user.CommentBlob = key
		//} else {
		//	userState.Comment = nil
		//}

		broadcast = true
	}

	if userState.Mute != nil || userState.Deaf != nil || userState.Suppress != nil || userState.PrioritySpeaker != nil {
		if userState.Deaf != nil {
			target.Deaf = *userState.Deaf
			if target.Deaf {
				userState.Mute = proto.Bool(true)
			}
		}
		if userState.Mute != nil {
			target.Mute = *userState.Mute
			if !target.Mute {
				userState.Deaf = proto.Bool(false)
				target.Deaf = false
			}
		}
		if userState.Suppress != nil {
			target.Suppress = *userState.Suppress
		}
		if userState.PrioritySpeaker != nil {
			target.PrioritySpeaker = *userState.PrioritySpeaker
		}
		broadcast = true
	}

	if userState.Recording != nil && *userState.Recording != target.Recording {
		target.Recording = *userState.Recording

		textMessage := &mumbleproto.TextMessage{}
		textMessage.TreeID = append(textMessage.TreeID, uint32(0))
		if target.Recording {
			// TODO: Should be bodynot message if the object is called message, or content or payload or data
			textMessage.Message = proto.String(fmt.Sprintf("User '%s' started recording", target.ShownName()))
		} else {
			textMessage.Message = proto.String(fmt.Sprintf("User '%s' stopped recording", target.ShownName()))
		}

		server.broadcastProtoMessageWithPredicate(textMessage, func(client *Client) bool {
			return client.Version < 0x10203
		})

		broadcast = true
	}

	userRegistrationChanged := false
	if userState.UserID != nil {
		uid, err := server.RegisterClient(target)
		if err != nil {
			// TODO: Why is message calling client methods? This is really bad isolation of logic
			//client.Printf("Unable to register: %v", err)
			userState.UserID = nil
		} else {
			userState.UserID = proto.Uint32(uid)
			client.user = server.Users[uid]
			userRegistrationChanged = true
		}
		broadcast = true
	}

	if userState.ChannelID != nil {
		channel, ok := server.Channels[*userState.ChannelID]
		// TODO: No not ok, use error, then you can actually inform dev/user/admin whats the fuck is going on
		if ok {
			server.userEnterChannel(target, channel, userState)
			broadcast = true
		}
	}

	if broadcast {
		// This variable denotes the length of a zlib-encoded "old-style" texture.
		// Mumble and Murmur used qCompress and qUncompress from Qt to compress
		// textures that were sent over the wire. We can use this to determine
		// whether a texture is a "new style" or an "old style" texture.
		texture := userState.Texture
		textureLength := uint32(0)
		if texture != nil && len(texture) > 4 {
			textureLength = uint32(texture[0])<<24 | uint32(texture[1])<<16 | uint32(texture[2])<<8 | uint32(texture[3])
		}
		if texture != nil && len(texture) > 4 && textureLength != 600*60*4 {
			// The sent texture is a new-style texture.  Strip it from the message
			// we send to pre-1.2.2 clients.
			userState.Texture = nil
			err := server.broadcastProtoMessageWithPredicate(userState, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic(errors.New("Unable to broadcast UserState"))
			}
			// Re-add it to the message, so that 1.2.2+ clients *do* get the new-style texture.
			userState.Texture = texture
		} else {
			// Old style texture.  We can send the message as-is.
			err := server.broadcastProtoMessageWithPredicate(userState, func(client *Client) bool {
				return client.Version < 0x10202
			})
			if err != nil {
				server.Panic(errors.New("Unable to broadcast UserState"))
			}
		}

		// If a texture hash is set on user, we transmit that instead of
		// the texture itself. This allows the client to intelligently fetch
		// the blobs that it does not already have in its local storage.
		if userState.Texture != nil && target.user != nil && target.user.HasTexture() {
			userState.Texture = nil
			userState.TextureHash = target.user.TextureBlobHashBytes()
		} else if target.user == nil {
			userState.Texture = nil
			userState.TextureHash = nil
		}

		// Ditto for comments.
		if userState.Comment != nil && target.user.HasComment() {
			userState.Comment = nil
			userState.CommentHash = target.user.CommentBlobHashBytes()
		} else if target.user == nil {
			userState.Comment = nil
			userState.CommentHash = nil
		}

		if userRegistrationChanged {
			server.ClearCaches()
		}

		err := server.broadcastProtoMessageWithPredicate(userState, func(client *Client) bool {
			return client.Version >= 0x10203
		})
		if err != nil {
			server.Panic(errors.New("Unable to broadcast UserState"))
		}
	}

	// TODO: Change freezing to writing to file, or use db
	//if target.IsRegistered() {
	//	server.UpdateFrozenUser(target, userState)
	//}
}

func (server *Server) handleBanListMessage(client *Client, message *Message) {
	banList := &mumbleproto.BanList{}
	err := proto.Unmarshal(message.buffer, banList)
	if err != nil {
		client.Panic(err)
		return
	}

	rootChannel := server.RootChannel()
	// TODO: Fix HasPermission
	//if !&rootChannel.ACL.HasPermission(client, BanPermission) {
	//	client.sendPermissionDenied(client, rootChannel, BanPermission)
	//	return
	//}

	if banList.Query != nil && *banList.Query != false {
		banList.Reset()

		server.banLock.RLock()
		defer server.banLock.RUnlock()

		for _, ban := range server.Bans {
			entry := &mumbleproto.BanList_BanEntry{}
			entry.Address = ban.IP
			entry.Mask = proto.Uint32(uint32(ban.Mask))
			entry.Name = proto.String(ban.Username)
			entry.Hash = proto.String(ban.CertificateHash)
			entry.Reason = proto.String(ban.Reason)
			entry.Start = proto.String(ban.ISOStartDate())
			// TODO: We may lose duration precision by converting it Uint32 from Uint64
			//entry.Duration = proto.Uint64(ban.Duration)
			entry.Duration = proto.Uint32(uint32(ban.Duration))
			banList.Bans = append(banList.Bans, entry)
		}
		if err := client.sendMessage(banList); err != nil {
			client.Panic(errors.New("Unable to send BanList"))
		}
	} else {
		server.banLock.Lock()
		defer server.banLock.Unlock()

		server.Bans = server.Bans[0:0]
		for _, entry := range banList.Bans {
			ban := Ban{}
			ban.IP = entry.Address
			ban.Mask = int(*entry.Mask)
			if entry.Name != nil {
				ban.Username = *entry.Name
			}
			if entry.Hash != nil {
				ban.CertificateHash = *entry.Hash
			}
			if entry.Reason != nil {
				ban.Reason = *entry.Reason
			}
			if entry.Start != nil {
				ban.SetISOStartDate(*entry.Start)
			}
			// TODO: Duration needs another look, it shuld be uint64 for good precision but stay backwards compatible with murmur
			if entry.Duration != nil {
				// TODO: This conversion from 32 wont probably work
				ban.Duration = int64(*entry.Duration)
			}
			server.Bans = append(server.Bans, ban)
		}

		// TODO: Remove frozen bans
		//server.UpdateFrozenBans(server.Bans)

		// TODO: Why is message calling client methods? This is really bad isolation of logic
		//client.Printf("BanList updated")
	}
}

// Broadcast text messages
func (server *Server) handleTextMessage(client *Client, message *Message) {
	textMessage := &mumbleproto.TextMessage{}
	err := proto.Unmarshal(message.buffer, textMessage)
	if err != nil {
		client.Panic(err)
		return
	}

	filtered, err := server.FilterText(*textMessage.Message)
	if err != nil {
		client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
		return
	}

	// TODO: Don't count entirely, we just want to know if there is something a position 0
	if len(filtered) == 0 {
		return
	}

	// TODO: Message has attribute message? No it has attribute body, content, data ...
	textMessage.Message = proto.String(filtered)

	clients := make(map[uint32]*Client)

	// Tree
	for _, channelID := range textMessage.TreeID {
		// TODO: Using okay doesnt give you the opportunity to explain wtf is ahppening
		if channel, ok := server.Channels[channelID]; ok {
			// TODO: Update hasPermission
			//if !&channel.ACL.HasPermission(client, TextMessagePermission) {
			//	client.sendPermissionDenied(client, channel, TextMessagePermission)
			//	return
			//}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-channel
	for _, channelID := range textMessage.ChannelID {
		if channel, ok := server.Channels[channelID]; ok {
			// TODO: HasPermission update
			//if !&channel.ACL.HasPermission(client, TextMessagePermission) {
			//	client.sendPermissionDenied(client, channel, TextMessagePermission)
			//	return
			//}
			for _, target := range channel.clients {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-clients
	for _, session := range textMessage.Session {
		// TODO: Fuck dont use ok, this doesnt provide info for the damonized server or dev
		if target, ok := server.clients[session]; ok {
			// TODO: HasPermission update
			//if !&target.Channel.ACL.HasPermission(client, TextMessagePermission) {
			//	client.sendPermissionDenied(client, target.Channel, TextMessagePermission)
			//	return
			//}
			clients[session] = target
		}
	}

	// Remove ourselves
	delete(clients, client.Session())

	for _, target := range clients {
		target.sendMessage(&mumbleproto.TextMessage{
			Actor:   proto.Uint32(client.Session()),
			Message: textMessage.Message,
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
	channel, ok := server.Channels[*acl.ChannelID]
	// TODO: return errors, so you can display them! This ok shit is not ok
	if !ok {
		return
	}

	// Does the user have permission to update or look at ACLs?
	// TODO: HasPermission update
	//if !&channel.acl.HasPermission(client, WritePermission) && !(channel.parent != nil && &channel.parent.acl.HasPermission(client, WritePermission)) {
	//	client.sendPermissionDenied(client, channel, WritePermission)
	//	return
	//}

	reply := &mumbleproto.ACL{}
	reply.ChannelID = &channel.ID

	channels := []*Channel{}
	users := map[int]bool{}

	// TODO: Ughh just comment all this bullshit out until I can fix the structure shit
	// Query the current ACL state for the channel
	//if Query != nil && *Query != false {
	//	reply.InheritACLs = proto.Bool(channel.ACL.InheritACL)
	//	// Walk the channel tree to get all relevant channels.
	//	// (Stop if we reach a channel that doesn't have the InheritACL flag set)
	//	// TODO: no, thats not necessary
	//	cacheChannel := channel
	//	for cacheChannel != nil {
	//		channels = append([]*Channel{cacheChannel}, channels...)
	//		if cacheChannel == channel || cacheChannel.ACL.InheritACL {
	//			// TODO: Doesn't seem right either
	//			cacheChannel = cacheChannel.parent
	//		} else {
	//			// TODO: Can't be right
	//			cacheChannel = nil
	//		}
	//	}

	//	// Construct the protobuf ChanACL objects corresponding to the ACLs defined
	//	// in our channel list.
	//	reply.ACLs = []*mumbleproto.ACL_ChanACL{}
	//	// TODO: just use proper storage, it will make the code smaller, eaiser to manage
	//	// Logic that does a specific task? Make it a function, it will make testing actually possible
	//	for _, channel := range channels {
	//		for _, childChannel := range channel.ACL.ACLs {
	//			if childChannel == channel || childChannel.ApplySubs {
	//				channelACL := &mumbleproto.ACL_ChanACL{}
	//				// TODO: lol no
	//				channelACL.Inherited = proto.Bool(channel != channel)
	//				channelACL.ApplyHere = proto.Bool(childChannel.ApplyHere)
	//				channelACL.ApplySubs = proto.Bool(childChannel.ApplySubs)
	//				if childChannel.UserID >= 0 {
	//					channelACL.UserID = childChannel.UserID
	//					users[childChannel.UserID] = true
	//				} else {
	//					channelACL.Group = proto.String(childChannel.Group)
	//				}
	//				channelACL.Grant = proto.Uint32(uint32(childChannel.Allow))
	//				channelACL.Deny = proto.Uint32(uint32(childChannel.Deny))
	//				reply.ACLs = append(reply.ACLs, channelACL)
	//			}
	//		}
	//	}

	//	parent := channel.parent
	//	allGroupNames := channel.ACL.GroupNames()

	//	// TODO: This file makes me want to quit programming, its makes me sad.

	//	// Construct the protobuf ChanGroups that we send back to the client.
	//	// Also constructs a usermap that is a set user ids from the channel's groups.
	//	reply.Groups = []*mumbleproto.ACL_ChanGroup{}
	//	for _, groupName := range allGroupNames {
	//		// TODO: FIX THIS!
	//		// Initializing all of these varialbles EVERYTIME through this god damn loop!
	//		var (
	//			group          Group
	//			parentGroup    Group
	//			hasGroup       bool
	//			hasParentGroup bool
	//		)

	//		group, hasGroup = channel.ACL.Groups[groupName]
	//		if parent != nil {
	//			parentGroup, hasParentGroup = parent.ACL.Groups[groupName]
	//		}

	//		protocolGroup := &mumbleproto.ACL_ChanGroup{}
	//		protocolGroup.Name = proto.String(groupName)

	//		protocolGroup.Inherit = proto.Bool(true)
	//		if hasGroup {
	//			protocolGroup.Inherit = proto.Bool(group.Inherit)
	//		}

	//		protocolGroup.Inheritable = proto.Bool(true)
	//		if hasGroup {
	//			protocolGroup.Inheritable = proto.Bool(group.Inheritable)
	//		}

	//		protocolGroup.Inherited = proto.Bool(hasParentGroup && parentGroup.Inheritable)

	//		// Add the set of user ids that this group affects to the user map.
	//		// This is used later on in this function to send the client a QueryUsers
	//		// message that maps user ids to usernames.
	//		if hasGroup {
	//			members := map[int]bool{}
	//			for uid, _ := range group.Add {
	//				users[uid] = true
	//				members[uid] = true
	//			}
	//			for uid, _ := range group.Remove {
	//				users[uid] = true
	//				delete(members, uid)
	//			}
	//			for uid, _ := range members {
	//				// TODO: This should already be a fucking uint32, if you are converting on every comparison you are doing something wrong, rethink your data types
	//				protocolGroup.Add = append(protocolGroup.Add, uint32(uid))
	//			}
	//		}
	//		if hasParentGroup {
	//			for uid, _ := range parentGroup.MembersInContext(&parent.ACL) {
	//				users[uid] = true
	//				protocolGroup.InheritedMembers = append(protocolGroup.InheritedMembers, uint32(uid))
	//			}
	//		}

	//		reply.Groups = append(reply.Groups, protocolGroup)
	//	}

	//	if err := client.sendMessage(reply); err != nil {
	//		client.Panic(err)
	//		return
	//	}

	//	// TODO: EVEN IF YOU WERE GOING TO DO THIS, WHY not do it in a fucking seperate function? this is like 400 lines, there was no way you could ever write tests for this.
	//	// Map the user ids in the user map to usernames of users.
	//	queryUsers := &mumbleproto.QueryUsers{}
	//	for uid, _ := range users {
	//		user, ok := server.Users[uid]
	//		if !ok {
	//			client.Printf("Invalid user id in ACL")
	//			continue
	//		}
	//		queryUsers.IDs = append(queryUsers.IDs, uint32(uid))
	//		queryUsers.Names = append(queryUsers.Names, user.Name)
	//	}
	//	if len(queryusers.IDs) > 0 {
	//		client.sendMessage(queryUsers)
	//	}
	//	// Set new groups and ACLs
	//} else {
	//	// Get old temporary members
	//	oldTemporaryMembers := map[string]map[int]bool{}
	//	for name, group := range channel.ACL.Groups {
	//		oldtmp[name] = group.Temporary
	//	}

	//	// Clear current ACLs and groups
	//	channel.ACL.ACLs = []acl.ACL{}
	//	channel.ACL.Groups = map[string]acl.Group{}

	//	// TODO: This repeats WAY to much and is unreadable and full of potential issues
	//	// IT REQUIRES SIMPLIFICATION, for fucks sake, 1200 lines already? 73% fuck!

	//	// Add the received groups to the channel.
	//	channel.ACL.InheritACL = *parentACL.InheritACLs
	//	for _, relatedGroup := range parentACL.Groups {
	//		channelGroup := acl.EmptyGroupWithName(*relatedGroup.Name)

	//		channelGroup.Inherit = *relatedGroup.Inherit
	//		channelGroup.Inheritable = *relatedGroup.Inheritable
	//		for _, uid := range relatedGroup.Add {
	//			channelGroup.Add[int(uid)] = true
	//		}
	//		for _, uid := range relatedGroup.Remove {
	//			channelGroup.Remove[int(uid)] = true
	//		}
	//		// TODO: Not ok! Use err, have the error hold the message to display, be consistent!
	//		if temporaryMembers, ok := oldTemporaryMembers[*relatedGroup.Name]; ok {
	//			channelGroup.Temporary = temporaryMembers
	//		}

	//		channel.ACL.Groups[channelGroup.Name] = channelGroup
	//	}
	//	// Add the received ACLs to the channel.
	//	for _, inheritedACL := range parentACL.ACLs {
	//		channelACL := acl.ACL{}
	//		// TODO: Stop repeating shit
	//		channelACL.ApplyHere = *inheritedACL.ApplyHere
	//		channelACL.ApplySubs = *inheritedACL.ApplySubs
	//		if pbacl.UserId != nil {
	//			// TODO: IF this userID is the admin? Why not AdminID
	//			// TODO: Stop conerting IDs so much!
	//			channelACL.UserID = int(*inheritedACL.UserID)
	//		} else {
	//			channelACL.Group = *inheritedACL.Group
	//		}
	//		channelACL.Deny = acl.Permission(*inheritedACL.Deny & acl.AllPermissions)
	//		channelACL.Allow = acl.Permission(*inheritedACL.Grant & acl.AllPermissions)

	//		channel.ACL.ACLs = append(channel.ACL.ACLs, channelACL)
	//	}

	//	// Clear the Server's caches
	//	server.ClearCaches()

	//	// Regular user?
	//	if !acl.HasPermission(&channel.ACL, client, acl.WritePermission) && client.IsRegistered() || client.HasCertificate() {
	//		channelACL := acl.ACL{}
	//		// TODO: Oh come on. This should not be just statically coded like this, 500 lines in
	//		channelACL.ApplyHere = true
	//		channelACL.ApplySubs = false
	//		if client.IsRegistered() {
	//			chanacl.UserID = client.UserID()
	//		} else if client.HasCertificate() {
	//			channelACL.Group = "$" + client.CertificateHash()
	//		}
	//		channelACL.Deny = acl.Permission(acl.NonePermission)
	//		channelACL.Allow = acl.Permission(acl.WritePermission | acl.TraversePermission)

	//		channel.ACL.ACLs = append(channel.ACL.ACLs, channelACL)
	//		// TODO: Replicate this everywhere and shrink all functions, its just too much for anyone to really test, manage, debug, etc. Just wastes time
	//		server.ClearCaches()
	//	}

	//	// Update freezer
	//	server.UpdateFrozenChannelACLs(channel)
	//}
}

// User query
func (server *Server) handleQueryUsers(client *Client, message *Message) {
	query := &mumbleproto.QueryUsers{}
	err := proto.Unmarshal(message.buffer, query)
	if err != nil {
		client.Panic(err)
		return
	}

	// TODO: Don't do this, servers daemonize, so use a centralized logging system controlled by configuration
	//server.Printf("in handleQueryUsers")

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
	//extended = acl.HasPermission(&rootChannel.ACL, client, acl.RegisterPermission)

	// If the client wasn't granted extended permissions, only allow it to query
	// users in channels it can enter.
	// TODO: HasPermission update
	//if !extended && !acl.HasPermission(&target.Channel.ACL, client, acl.EnterPermission) {
	//	client.sendPermissionDenied(client, target.Channel, acl.EnterPermission)
	//	return
	//}

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
		client.Panic(err)
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

	channel := server.Channels[*query.ChannelID]
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
					// TODO: Replace this shit alter, just get the first major structure changes in
					//buffer, err := blobStore.Get(target.user.TextureBlob)
					//if err != nil {
					//	server.Panic(err)
					//	return
					//}
					//userState.Reset()
					//userState.Session = proto.Uint32(uint32(target.Session()))
					//// TODO: What is a texture????? BETTER NAMES
					//userState.Texture = buffer
					//if err := client.sendMessage(userState); err != nil {
					//	client.Panic(err)
					//	return
					//}
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
					// TODO: Ughh just comment blob shit out now for the first major structure changes to work and tackle this after
					//buffer, err := requestBlob.Get(target.user.CommentBlob)
					//if err != nil {
					//	// TODO: There is no reason to repeat these fucntions for each class, its just bad
					//	server.Panicf("Blobstore error: %v", err)
					//	return
					//}
					//userState.Reset()
					//userState.Session = proto.Uint32(uint32(target.Session()))
					//userState.Comment = proto.String(string(buffer))
					//if err := client.sendMessage(userState); err != nil {
					//	client.Panic(err)
					//	return
					//}
				}
			}
		}
	}

	channelState := &mumbleproto.ChannelState{}

	// Request for channel descriptions
	// TODO: Added up, there is SO MUCH WASTE. THESE ARE PER MESSAGE!
	if len(requestBlob.ChannelDescription) > 0 {
		for _, cid := range requestBlob.ChannelDescription {
			if channel, ok := server.Channels[cid]; ok {
				if channel.HasDescription() {
					channelState.Reset()
					//buffer, err := requestBlob.Get(channel.DescriptionBlob)
					//if err != nil {
					//	server.Panic(err)
					//	return
					//}
					//// TODO: you should be asking yourself, if you are doing a conversion everytime you use a variable, is there something majorly wrong? the answer is yes
					//channelState.ChannelID = proto.Uint32(channel.ID)
					//channelState.Description = proto.String(string(buffer))
					//if err := client.sendMessage(channelState); err != nil {
					//	client.Panic(err)
					//	return
					//}
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
	// TODO: HasPermission needs updating
	//if !&rootChannel.ACL.HasPermission(client, RegisterPermission) {
	//	client.sendPermissionDenied(client, rootChannel, RegisterPermission)
	//	// TODO: Second time this came up atlest and if you used an error it would be consistent
	//	return
	//}

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
						//err := tx.Put(&freezer.UserRemove{ID: listUser.UserID})
						// TODO: If you made this a function you could reduce maybe 100 lines per file
						//if err != nil {
						//	server.Fatal(err)
						//}
					} else {
						// Rename user
						// todo(mkrautz): Validate name.
						user.Name = *listUser.Name
						//err := tx.Put(&freezer.User{ID: listUser.UserID, Name: listUser.Name})
						//if err != nil {
						//	server.Fatal(err)
						//}
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
