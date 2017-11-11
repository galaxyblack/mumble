package protocol

import (
	"net"
	"time"

	"github.com/golang/protobuf/proto"
)

const (
	ISODate = "2006-01-02T15:04:05"
)

type Ban struct {
	//IP              net.IP
	//Mask            int
	//Username        string
	//CertificateHash string
	//Reason          string
	//Start           int64
	//Duration        int64
	IPAddress []byte `protobuf:"bytes,1,opt,name=ip" json:"ip,omitempty"`
	// TODO: Think about using other client attributes to ban to avoid just jumping IP
	// TODO: Why are these all pointers? Is there a major advantage to this? It makes things less threadsafe and error prone and the data being passed around would not be that large
	Mask             uint32 `protobuf:"varint,2,opt,name=mask" json:"mask,omitempty"`
	Username         string `protobuf:"bytes,3,opt,name=username" json:"username,omitempty"`
	CertificateHash  string `protobuf:"bytes,4,opt,name=cert_hash" json:"cert_hash,omitempty"`
	Reason           string `protobuf:"bytes,5,opt,name=reason" json:"reason,omitempty"`
	Start            int64  `protobuf:"varint,6,opt,name=start" json:"start,omitempty"`
	Duration         int64  `protobuf:"varint,7,opt,name=duration" json:"duration,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

// TODO: this? inconsistent usage and i prefer self, will just continue scheme used other places.
// so a JS programmer? explains  ALOT :p
func (ban *Ban) Reset()         { *ban = Ban{} }
func (ban *Ban) String() string { return proto.CompactTextString(ban) }
func (*Ban) ProtoMessage()      {}

func (ban *Ban) GetIPAddress() []byte {
	// TODO: Move validations to own funcs
	//if ban != nil
	return ban.IPAddress
}

func (ban *Ban) GetMask() uint32 {
	// TODO: Move validations to own funcs
	//if ban != nil && ban.Mask != nil
	return ban.Mask
}

func (ban *Ban) GetUsername() string {
	// TODO: Move validations to own funcs
	//if ban != nil && ban.Username != nil
	return ban.Username
	// TODO: seems like this should be caught with an error or validated against in other places if this is even possible. dont return ""
}

func (ban *Ban) GetCertificateHash() string {
	// TODO: Move validations to own funcs
	//if ban != nil && ban.CertificateHash != nil {
	return ban.CertificateHash
}

func (ban *Ban) GetReason() string {
	// TODO: Move validations to own funcs
	//if ban != nil && ban.Reason != nil
	return ban.Reason
}

// Create a net.IPMask from a specified amount of mask bits
func (ban Ban) IPMask() (mask net.IPMask) {
	allBits := ban.Mask
	for i := 0; i < 16; i++ {
		bits := allBits
		if bits > 0 {
			if bits > 8 {
				bits = 8
			}
			mask = append(mask, byte((1<<uint(bits))-1))
		} else {
			mask = append(mask, byte(0))
		}
		allBits -= 8
	}
	return
}

// Check whether an IP matches a Ban
func (ban Ban) Match(ip net.IP) bool {
	// TODO Fuck no
	//banned := ban.IP.Mask(ban.IPMask())
	//masked := ip.Mask(ban.IPMask())
	//return banned.Equal(masked)
	return false
}

// Set Start date from an ISO 8601 date (in UTC)
func (ban *Ban) SetISOStartDate(isodate string) {
	startTime, err := time.Parse(ISODate, isodate)
	if err != nil {
		ban.Start = 0
	} else {
		ban.Start = startTime.Unix()
	}
}

// Return the currently set start date as an ISO 8601-formatted
// date (in UTC).
func (ban Ban) ISOStartDate() string {
	startTime := time.Unix(ban.Start, 0).UTC()
	return startTime.Format(ISODate)
}

// Check whether a ban has expired
func (ban Ban) IsExpired() bool {
	// ∞-case
	if ban.Duration == 0 {
		return false
	}

	// Expiry check
	expiryTime := ban.Start + ban.Duration
	if time.Now().Unix() > expiryTime {
		return true
	}
	return false
}
