package protocol

import "errors"

// Writer errors
var (
	ErrTxGroupFull        = errors.New("transction group is full")
	ErrTxGroupValueTooBig = errors.New("value too big to put inside the txgroup")
)

// Walker errors
var (
	ErrUnexpectedEndOfRecord   = errors.New("unexpected end of record")
	ErrCRC32Mismatch           = errors.New("CRC32 mismatch")
	ErrRemainingBytesForRecord = errors.New("remaining bytes in record")
	ErrRecordTooBig            = errors.New("the record in the file is too big")
)
