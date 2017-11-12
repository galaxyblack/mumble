package mumble

import (
	"encoding/hex"

	"github.com/golang/protobuf/proto"
)

// A Mumble channel
type Channel struct {
	temporary bool
	clients   map[uint32]*Client
	parent    *Channel
	children  map[uint32]*Channel
	// Links
	// TODO: Links is a map of channels? Thats not intuitive
	Links map[uint32]*Channel
	// Blobs
	// TODO: Why not use the Blob object? Lol seriously, whats the point of the blob object then?
	ID         uint32   `protobuf:"varint,1,opt,name=id" json:"id,omitempty"`
	Name       string   `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	ParentID   uint32   `protobuf:"varint,3,opt,name=parent_id" json:"parent_id,omitempty"`
	Position   int32    `protobuf:"varint,4,opt,name=position" json:"position,omitempty"`
	InheritACL bool     `protobuf:"varint,5,opt,name=inherit_acl" json:"inherit_acl,omitempty"`
	LinkIDs    []uint32 `protobuf:"varint,6,rep,name=links" json:"links,omitempty"`
	// ACL - Access control list
	ACLs             []ACL   `protobuf:"bytes,7,rep,name=acl" json:"acl,omitempty"`
	Groups           []Group `protobuf:"bytes,8,rep,name=groups" json:"groups,omitempty"`
	DescriptionBlob  string  `protobuf:"bytes,9,opt,name=description_blob" json:"description_blob,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (channel *Channel) Reset()         { *channel = Channel{} }
func (channel *Channel) String() string { return proto.CompactTextString(channel) }
func (channel *Channel) ProtoMessage()  {}

func (channel *Channel) GetID() uint32 {
	// TODO: Move validations to own funcs
	//if channel != nil && channel.ID != nil {
	return channel.ID
	//}
	//return 0
}

func (channel *Channel) GetName() string {
	// TODO: Move validations to own funcs
	//if channel != nil && channel.Name != nil {
	return channel.Name
	//}
	//return ""
}

func (channel *Channel) GetParentID() uint32 {
	// TODO: Move validations to own funcs
	//if channel != nil && channel.ParentID != nil {
	return channel.ParentID
	//}
	//return 0
}

func (channel *Channel) GetPosition() int32 {
	// TODO: Move validations to own funcs
	//if channel != nil && chnanel.Position != nil {
	return channel.Position
	//}
	//return 0
}

func (channel *Channel) GetInheritACL() bool {
	// TODO: Move these validations
	//if channel != nil && channel.InheritACL != nil {
	return channel.InheritACL
	//}
	//return false
}

func NewChannel(id uint32, name string) (channel *Channel) {
	// TODO: There are clearner ways to do this
	channel = new(Channel)
	channel.ID = id
	channel.Name = name
	channel.clients = make(map[uint32]*Client)
	channel.children = make(map[uint32]*Channel)
	// TODO: Switched to map[string]string since acl.Group is just a string
	channel.Groups = []Group{}
	channel.Links = make(map[uint32]*Channel)
	return
}

// Add a child channel to a channel
func (channel *Channel) AddChild(child *Channel) {
	child.parent = channel
	// TODO: This is absurd, no parent functionality existed in ACL and why use maps if we are going to be implemneted relations? You already have an SQL database impelmented!
	// Started fixing this by adding IDs to ACLs and implementing a ParentID, so we can track basic parent relations but this should just be re-implemented properly because
	// this is a mess that is bound to lead to bugs
	// TODO: FIX THIS, channel doesnt have ACL
	//child.ACL.ParentID = channel.ACL.ID
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
	// TODO: Dont need to count every character of a block if you are just validaing its not empty
	return len(channel.DescriptionBlob) > 0
}

// Get the channel's blob hash as a byte slice for sending via a protobuf message.
// Returns nil if there is no blob.
func (channel *Channel) DescriptionBlobHashBytes() (buffer []byte) {
	buffer, err := hex.DecodeString(channel.DescriptionBlob)
	if err != nil {
		return nil
	}
	return buffer
}

// Returns a slice of all channels in this channel's
// link chain.
// TODO: Use embedded DB
func (channel *Channel) AllLinks() (seen map[uint32]*Channel) {
	seen = make(map[uint32]*Channel)
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
// TODO: Sub channels all of a sudden? EVERYWHERE else is child
func (channel *Channel) ChildChannels() (seen map[uint32]*Channel) {
	seen = make(map[uint32]*Channel)
	walk := []*Channel{}
	// TODO: This is a empty validation, fix this!
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
// TODO: Why is this like NEVER used? Also dont count over index clients
func (channel *Channel) IsEmpty() bool {
	// TODO: This is my new preferred way to check if empty over length checks, hope it actually works
	return (channel.clients[0] == nil)
}
