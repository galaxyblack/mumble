package protocol

import (
	"encoding/hex"
)

// A Mumble channel
type Channel struct {
	ID       int
	Name     string
	Position int

	temporary bool
	clients   map[uint32]*Client
	parent    *Channel
	children  map[int]*Channel

	// ACL - Access control list
	ACL acl

	// Links
	Links map[int]*Channel

	// Blobs
	// TODO: Why not use the Blob object? Lol seriously, whats the point of the blob object then?
	DescriptionBlob string
}

func NewChannel(id int, name string) (channel *Channel) {
	channel = new(Channel)
	channel.ID = id
	channel.Name = name
	channel.clients = make(map[uint32]*Client)
	channel.children = make(map[int]*Channel)
	// TODO: Switched to map[string]string since acl.Group is just a string
	channel.ACL.Groups = make(map[string]string)
	channel.Links = make(map[int]*Channel)
	return
}

// Add a child channel to a channel
func (channel *Channel) AddChild(child *Channel) {
	child.parent = channel
	// TODO: This is absurd, no parent functionality existed in ACL and why use maps if we are going to be implemneted relations? You already have an SQL database impelmented!
	// Started fixing this by adding IDs to ACLs and implementing a ParentID, so we can track basic parent relations but this should just be re-implemented properly because
	// this is a mess that is bound to lead to bugs
	child.ACL.ParentID = channel.ACL.ID
	channel.children[child.ID] = child
}

// Remove a child channel from a parent
func (channel *Channel) RemoveChild(child *Channel) {
	child.parent = nil
	// TODO: Parent did not exist for ACL, and why would we be storing a full ACL inside of an ACL? This type of recursion is not possible or desirable (at least in this case)
	// this is a fucking uint32 so it can't be nil, it has to be a uint32, as thats what IDS are! And if the channel is being removed what the fuck are we doing? WOW
	//child.ACL.ParentID = nil
	delete(channel.children, child.ID)
}

// Add client
func (channel *Channel) AddClient(client *Client) {
	channel.clients[client.Session()] = client
	client.Channel = channel
}

// Remove client
func (channel *Channel) RemoveClient(client *Client) {
	delete(channel.clients, client.Session())
	client.Channel = nil
}

// Does the channel have a description?
func (channel *Channel) HasDescription() bool {
	return len(channel.DescriptionBlob) > 0
}

// Get the channel's blob hash as a byte slice for sending via a protobuf message.
// Returns nil if there is no blob.
func (channel *Channel) DescriptionBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(channel.DescriptionBlob)
	if err != nil {
		return nil
	}
	return buf
}

// Returns a slice of all channels in this channel's
// link chain.
func (channel *Channel) AllLinks() (seen map[int]*Channel) {
	seen = make(map[int]*Channel)
	walk := []*Channel{channel}
	for len(walk) > 0 {
		current := walk[len(walk)-1]
		walk = walk[0 : len(walk)-1]
		for _, linked := range current.Links {
			if _, alreadySeen := seen[linked.ID]; !alreadySeen {
				seen[linked.ID] = linked
				walk = append(walk, linked)
			}
		}
	}
	return
}

// Returns a slice of all of this channel's subchannels.
func (channel *Channel) AllSubChannels() (seen map[int]*Channel) {
	seen = make(map[int]*Channel)
	walk := []*Channel{}
	if len(channel.children) > 0 {
		walk = append(walk, channel)
		for len(walk) > 0 {
			current := walk[len(walk)-1]
			walk = walk[0 : len(walk)-1]
			for _, child := range current.children {
				if _, alreadySeen := seen[child.ID]; !alreadySeen {
					seen[child.ID] = child
					walk = append(walk, child)
				}
			}
		}
	}
	return
}

// Checks whether the channel is temporary
func (channel *Channel) IsTemporary() bool {
	return channel.temporary
}

// Checks whether the channel is temporary
func (channel *Channel) IsEmpty() bool {
	return len(channel.clients) == 0
}
