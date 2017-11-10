package protocol

import (
	"net"
	"time"
)

const (
	ISODate = "2006-01-02T15:04:05"
)

type Ban struct {
	IP              net.IP
	Mask            int
	Username        string
	CertificateHash string
	Reason          string
	Start           int64
	Duration        int64
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
	banned := ban.IP.Mask(ban.IPMask())
	masked := ip.Mask(ban.IPMask())
	return banned.Equal(masked)
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
