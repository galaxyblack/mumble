package protocol

import (
	"encoding/hex"
	"errors"
)

// This file implements Server's handling of Users.
// Users are registered clients on the server.

type User struct {
	ID              uint32
	Session         uint32
	Name            string
	Password        string
	CertHash        string
	Email           string
	TextureBlob     string
	CommentBlob     string
	LastChannelID   uint32
	LastActive      uint64
	CertificateHash string
	Tokens          []string
	// CUSTOM
	Roles []string
}

// Create a new User
func NewUser(id uint32, name string) (user *User, err error) {
	if id < 0 {
		return nil, errors.New("Invalid user id")
	}
	if len(name) == 0 {
		return nil, errors.New("Invalid username")
	}

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
