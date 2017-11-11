package protocol

import (
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"
	"math"
	//"github.com/golang/protobuf/proto"
)

// Checks whether the error err is an EOF
// error.
func isEOF(err error) bool {
	// TODO: Just return result of if not if then returning newly formed bools
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return true
	}
	return false
}

// Type Walker implements a method for
// iterating the transaction groups of an
// immutable Log.
type Walker struct {
	reader io.Reader
}

// Type txReader imlpements a checksumming reader, intended
// for reading transaction groups of a Log.
//
// Besides auto-checksumming the read content, it also
// keeps track of the amount of consumed bytes.
type txReader struct {
	reader   io.Reader
	crc32    hash.Hash32
	consumed int
}

// Create a new txReader for reading a transaction group
// from the log.
func newTxReader(reader io.Reader) *txReader {
	txr := new(txReader)
	txr.reader = reader
	txr.crc32 = crc32.NewIEEE()
	return txr
}

// walkReader's Read method. Reads from walkReader's Reader
// and checksums while reading.
func (txr *txReader) Read(p []byte) (n int, err error) {
	n, err = txr.reader.Read(p)
	if err != nil && err != io.EOF {
		return
	}
	txr.consumed += n

	_, crc32err := txr.crc32.Write(p)
	if crc32err != nil {
		return n, crc32err
	}

	return n, err
}

// Sum32 returns the IEEE-style CRC32 checksum
// of the data read by the walkReader.
func (txr *txReader) Sum32() uint32 {
	return txr.crc32.Sum32()
}

// Consumed returns the amount of bytes consumed by
// the walkReader.
func (txr *txReader) Consumed() int {
	return txr.consumed
}

// Create a new Walker that iterates over the log entries of a given Reader.
func NewReaderWalker(reader io.Reader) (walker *Walker, err error) {
	walker = new(Walker)
	walker.reader = reader
	return walker, nil
}

// Next returns the next transaction group in the log as a slice of
// pointers to the protobuf-serialized log entries.
//
// This method will only attempt to serialize types with type identifiers
// that this package knows of. In case an unknown type identifier is found
// in a transaction group, it is silently ignored (it's skipped).
//
// On error, Next returns a nil slice and a non-nil err.
// When the end of the file is reached, Next returns nil, os.EOF.
func (walker *Walker) Next() (entries []interface{}, err error) {
	// TODO: Move to struct
	var (
		remainBytes uint32
		remainOps   uint32
		crcsum      uint32
		kind        uint16
		length      uint16
	)

	err = binary.Read(walker.reader, binary.LittleEndian, &remainBytes)
	if isEOF(err) {
		return nil, io.EOF
	} else if err != nil {
		return nil, err
	}

	if remainBytes < 8 {
		return nil, ErrUnexpectedEndOfRecord
	}
	if remainBytes-8 > math.MaxUint8*math.MaxUint16 {
		return nil, ErrRecordTooBig
	}

	err = binary.Read(walker.reader, binary.LittleEndian, &remainOps)
	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	} else if err != nil {
		return nil, err
	}

	err = binary.Read(walker.reader, binary.LittleEndian, &crcsum)
	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	} else if err != nil {
		return nil, err
	}

	remainBytes -= 8
	reader := newTxReader(walker.reader)

	for remainOps > 0 {
		err = binary.Read(reader, binary.LittleEndian, &kind)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		err = binary.Read(reader, binary.LittleEndian, &length)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		buffer := make([]byte, length)
		_, err = io.ReadFull(reader, buffer)
		if isEOF(err) {
			break
		} else if err != nil {
			return nil, err
		}

		// TODO: ServerType isn't real, because I got rid of the writer.go file and other missing things in this section
		//switch typeKind(kind) {
		//case ServerType:
		//	server := &Server{}
		//	err = proto.Unmarshal(buffer, server)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, server)
		//case ConfigKVType:
		//	config := &ConfigKV{}
		//	err = proto.Unmarshal(buffer, config)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, config)
		//case BanListType:
		//	banList := &BanList{}
		//	err = proto.Unmarshal(buffer, banList)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, banList)
		//case UserType:
		//	user := &User{}
		//	err = proto.Unmarshal(buffer, user)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, user)
		//case UserRemoveType:
		//	userRemove := &UserRemove{}
		//	err = proto.Unmarshal(buffer, userRemove)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, userRemove)
		//case ChannelType:
		//	channel := &Channel{}
		//	err = proto.Unmarshal(buffer, channel)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, channel)
		//case ChannelRemoveType:
		//	channelRemove := &ChannelRemove{}
		//	err = proto.Unmarshal(buffer, channelRemove)
		//	if isEOF(err) {
		//		break
		//	} else if err != nil {
		//		return nil, err
		//	}
		//	entries = append(entries, channelRemove)
		//}

		//remainOps -= 1
		continue
	}

	if isEOF(err) {
		return nil, ErrUnexpectedEndOfRecord
	}

	if reader.Consumed() != int(remainBytes) {
		return nil, ErrRemainingBytesForRecord
	}

	if reader.Sum32() != crcsum {
		return nil, ErrCRC32Mismatch
	}

	return entries, nil
}
