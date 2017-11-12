package mumble

//import ()

// A VoiceTarget holds information about a single
// VoiceTarget entry of a Client.
type VoiceTarget struct {
	sessions []uint32
	channels []Channel

	directCache       map[uint32]*Client
	fromChannelsCache map[uint32]*Client
}

// TODO: Wtf? Just use a god damn channel struct!!!!!!!
//type voiceTargetChannel struct {
//	id            uint32
//	childChannels bool
//	links         bool
//	onlyGroup     string
//}

// Add's a client's session to the VoiceTarget
func (voiceTarget *VoiceTarget) AddSession(session uint32) {
	voiceTarget.sessions = append(voiceTarget.sessions, session)
}

// Add a channel to the VoiceTarget.
// If subchannels is true, any sent voice packets will also be sent to all subchannels.
// If links is true, any sent voice packets will also be sent to all linked channels.
// If group is a non-empty string, any sent voice packets will only be broadcast to members
// of that group who reside in the channel (or its children or linked channels).
func (voiceTarget *VoiceTarget) AddChannel(id uint32, children bool, links bool, group string) {
	voiceTarget.channels = append(voiceTarget.channels, Channel{
		ID: id,
		// TODO: Fix
		//children:  children,
		//links:     links,
		//onlyGroup: group,
	})
}

// Checks whether the VoiceTarget is empty (has no targets)
func (voiceTarget *VoiceTarget) IsEmpty() bool {
	// TODO: Feel like should not need to be counting past 0 to check if these are nil/empty. Wasting CPU
	return len(voiceTarget.sessions) == 0 && len(voiceTarget.channels) == 0
}

// Clear the VoiceTarget's cache.
func (voiceTarget *VoiceTarget) ClearCache() {
	voiceTarget.directCache = nil
	voiceTarget.fromChannelsCache = nil
}

// Send the contents of the VoiceBroadcast to all targets specified in the
// VoiceTarget.
func (voiceTarget *VoiceTarget) SendVoiceBroadcast(voiceBroadcast *VoiceBroadcast) {
	buffer := voiceBroadcast.buffer
	client := voiceBroadcast.client
	server := client.server

	direct := voiceTarget.directCache
	fromChannels := voiceTarget.fromChannelsCache

	if direct == nil || fromChannels == nil {
		direct = make(map[uint32]*Client)
		fromChannels = make(map[uint32]*Client)

		for _, voiceTargetChannel := range voiceTarget.channels {
			channel := server.Channels[voiceTargetChannel.ID]
			// TODO: This is a validation, get this in its own function, stop writing 200 line god damn functions
			if channel == nil {
				continue
			}

			// TODO: Move validation to own func
			//if !voiceTargetChannel.children && !voiceTargetChannel.links && voiceTargetChannel.onlyGroup == "" {
			// TODO: Fix after fixing Haspermission
			//if HasPermission(&channel.ACL, client, acl.WhisperPermission) {
			//	for _, target := range channel.clients {
			//		fromChannels[target.Session()] = target
			//	}
			//}
			//} else {
			// TODO: WTF? Use the Channel object, stop this voiceTargetChannel bs
			//	server.Printf("%v", voiceTargetChannel)
			//	newChannels := make(map[int]*Channel)
			//	if voiceTargetChannel.links {
			//		newChannels = channel.AllLinks()
			//	} else {
			//		newChannels[channel.ID] = channel
			//	}
			//	if voiceTargetChannel.childChannels {
			//		childChannels := channel.AllChildChannels()
			//		for key, value := range childChannels {
			//			newChannels[key] = value
			//		}
			//	}
			//	for _, newChannel := range newChannels {
			//		if acl.HasPermission(&newChannel.ACL, client, acl.WhisperPermission) {
			//			for _, target := range newChannel.clients {
			//				if voiceTargetChannel.onlyGroup == "" || acl.GroupMemberCheck(&newChannel.ACL, &newChannel.ACL, voiceTargetChannel.onlyGroup, target) {
			//					fromChannels[target.Session()] = target
			//				}
			//			}
			//		}
			//	}
			//}
		}

		for _, session := range voiceTarget.sessions {
			target := server.clients[session]
			if target != nil {
				if _, alreadyInFromChannels := fromChannels[target.Session()]; !alreadyInFromChannels {
					direct[target.Session()] = target
				}
			}
		}

		// Make sure we don't send to ourselves.
		delete(direct, client.Session())
		delete(fromChannels, client.Session())

		if voiceTarget.directCache == nil {
			voiceTarget.directCache = direct
		}

		if voiceTarget.fromChannelsCache == nil {
			voiceTarget.fromChannelsCache = fromChannels
		}
	}

	kind := buffer[0] & 0xe0

	if len(fromChannels) > 0 {
		for _, target := range fromChannels {
			buffer[0] = kind | 2
			err := target.SendUDP(buffer)
			if err != nil {
				// TODO: Use central error logging system
				//target.Panic("Unable to send UDP packet: %v", err.Error())
			}
		}
	}

	if len(direct) > 0 {
		for _, target := range direct {
			buffer[0] = kind | 2
			target.SendUDP(buffer)
			err := target.SendUDP(buffer)
			if err != nil {
				// TODO: Use central error logging system
				//target.Panic("Unable to send UDP packet: %v", err.Error())
			}
		}
	}
}
