package protocol

import (
	"encoding/hex"
	//"errors"

	"github.com/golang/protobuf/proto"
)

// This file implements Server's handling of Users.
// Users are registered clients on the server.

type User struct {
	Session uint32
	Tokens  []string
	// CUSTOM
	Roles            []string
	ID               uint32 `protobuf:"varint,1,opt,name=id" json:"id,omitempty"`
	Name             string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	Password         string `protobuf:"bytes,3,opt,name=password" json:"password,omitempty"`
	CertificateHash  string `protobuf:"bytes,4,opt,name=cert_hash" json:"cert_hash,omitempty"`
	Email            string `protobuf:"bytes,5,opt,name=email" json:"email,omitempty"`
	TextureBlob      string `protobuf:"bytes,6,opt,name=texture_blob" json:"texture_blob,omitempty"`
	CommentBlob      string `protobuf:"bytes,7,opt,name=comment_blob" json:"comment_blob,omitempty"`
	LastChannelID    uint32 `protobuf:"varint,8,opt,name=last_channel_id" json:"last_channel_id,omitempty"`
	LastActive       uint64 `protobuf:"varint,9,opt,name=last_active" json:"last_active,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

func (user *User) Reset()         { *user = User{} }
func (user *User) String() string { return proto.CompactTextString(user) }
func (user *User) ProtoMessage()  {}

func (user *User) GetID() uint32 {
	// TODO: Move validations to own functions
	//if user != nil && user.ID != nil
	return user.ID
}

func (user *User) GetUsername() string {
	// TODO: Move validations to own functions
	//if user != nil && user.Name != nil
	return user.Name
}

func (user *User) GetPassword() string {
	// TODO: Move validations to own functions
	//if user != nil && user.Password != nil
	return user.Password
}

func (user *User) GetCertificateHash() string {
	// TODO: Move validations to own functions
	//if user != nil && user.CertificateHash != nil
	return user.CertificateHash
}

// Create a new User
func NewUser(id uint32, name string) (user *User, err error) {
	// TODO: Move validations to own functions
	//if id < 0 {
	//	return nil, errors.New("Invalid user id")
	//}
	//if len(name) == 0 {
	//	return nil, errors.New("Invalid username")
	//}

	return &User{
		ID:   id,
		Name: name,
	}, nil
}

// Does the channel have comment?
func (user *User) HasComment() bool {
	return len(user.CommentBlob) > 0
}

// Get the hash of the user's comment blob as a byte slice for transmitting via a protobuf message.
// Returns nil if there is no such blob.
func (user *User) CommentBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(user.CommentBlob)
	if err != nil {
		return nil
	}
	return buf
}

// Does the user have a texture?
func (user *User) HasTexture() bool {
	return len(user.TextureBlob) > 0
}

// Get the hash of the user's texture blob as a byte slice for transmitting via a protobuf message.
// Returns nil if there is no such blob.
func (user *User) TextureBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(user.TextureBlob)
	if err != nil {
		return nil
	}
	return buf
}
