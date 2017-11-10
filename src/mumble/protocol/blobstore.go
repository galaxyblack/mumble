package protocol

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// ErrorNoSuchKey signals that a blob with the given key does
	// not exist in the BlobStore.
	ErrorNoSuchKey = errors.New("blobStore: no such key")

	// ErrorBadKey signals that the given key is not well formed.
	ErrorBadKey = errors.New("blobStore: bad key")
)

// BlobStore represents a simple disk-persisted content addressible
// blob store that uses the file system for persistence.
//
// Blobs in the blobstore are indexed by their SHA1 hash.
//
// The BlobStore is backed by a directory on the filesystem. This
// directory contains subdirectories which contain keys (SHA1 hashes).
// Each subdirectory is named according to the first hex-encoded byte
// of the keys that subdirectory contains.
//
// For example, a file that has the content 'hello world' will have
// the SHA1 hash '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'. If our
// blobstore's backing directory is called 'blobstore', the blob with
// only 'hello world' in it will be stored as follows:
//
//     blobstore/2a/2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
//
// The BlobStore is self-synchronizing, relying on the filesystem
// operations to ensure atomicity. Thus, accessing a single BlobStore
// from multiple goroutines should have no ill side effects.
type BlobStore struct {
	directory string
}

// Open opens an existing BlobStore. The path parameter must
// point to a directory that already exists for correct
// operation, however, the Open function does not check that
// this is the case.
func Open(path string) BlobStore {
	return BlobStore{directory: path}
}

// isValidKey checks whether key is a valid BlobStore key.
func isValidKey(key string) bool {
	// SHA1 digests are 40 bytes long when hex-encoded.
	if len(key) != 40 {
		return false
	}

	// Check whether the string is valid hex-encoding.
	_, err := hex.DecodeString(key)
	if err != nil {
		return false
	}

	return true
}

// extractKeyComponents returns the directory and the fileName that the
// blob identified by key should be stored under in the BlobStore.
// This function also checks whether the key is valid. If not, it returns
// ErrBadKey.
func extractKeyComponents(key string) (directory string, fileName string, err error) {
	if !isValidKey(key) {
		return "", "", ErrorBadKey
	}
	return key[0:2], key, nil
}

// BlobStoreGet returns a byte slice containing the contents of
// the blob identified by key. If no such blob is found,
// BlobStoreGet returns ErrNoSuchKey.
// TODO: Can we just use a key/value store bitte?
func BlobStoreGet(key string) ([]byte, error) {
	directory, fileName, err := extractKeyComponents(key)
	if err != nil {
		return nil, err
	}

	// TODO: two dir what?
	blobFileName := filepath.Join(directory, fileName)
	file, err := os.Open(blobFileName)
	if os.IsNotExist(err) {
		return nil, ErrorNoSuchKey
	} else if err != nil {
		return nil, err
	}

	blobReader, err := newBlobReader(file, key)
	if err != nil {
		file.Close()
		return nil, err
	}
	defer blobReader.Close()

	buffer, err := ioutil.ReadAll(blobReader)
	if err != nil {
		return nil, err
	}

	return buffer, nil
}

// Put puts the contents of blob into the BlobStore. If
// the blob was successfully stored, the returned key can
// be used to retrieve the buf from the BlobStore at a
// later time.
// TODO: If this is goign to be a method, it doesnt need BlobStore in the title, but why does this work with puts but not get? need consistencey
func (blobStore BlobStore) BlobStorePut(buffer []byte) (key string, err error) {
	// Calculate the key for the blob.  We can't really delay it more than this,
	// since we need to know the key for the blob to check whether it's already on
	// disk.
	// TODO: Don't use sha1, same lib has better hashing
	hash := sha1.New()
	_, err = hash.Write(buffer)
	if err != nil {
		return "", err
	}
	key = hex.EncodeToString(hash.Sum(nil))

	// BlobstoreGet the components that make up the on-disk
	// path for the blob.
	directory, fileName, err := extractKeyComponents(key)
	if err != nil {
		return "", err
	}

	blobDirectory := filepath.Join(blobStore.directory, directory)
	blobPath := filepath.Join(blobDirectory, fileName)

	// Check if the blob already exists.
	_, err = os.Stat(blobPath)
	if err == nil {
		// The file already exists. Our job is done.
		return key, nil
	} else if os.IsNotExist(err) {
		// The blob does not exist on disk yet.
		// Fallthrough.
	} else if err != nil {
		return "", err
	}

	// Ensure that blobdir exist.
	err = os.Mkdir(blobDirectory, 0750)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	// Create a temporary file to write to.
	//
	// Once we're done, we can atomically rename the file
	// to the correct key.
	//
	// This method is racy: two callers can attempt to write
	// the same blob at the same time. This shouldn't affect
	// the consistency of the final blob, but worst case, we've
	// done some extra work.

	// TODO: remove all this for lib
	file, err := ioutil.TempFile(blobDirectory, fileName)
	if err != nil {
		return "", err
	}

	temporaryFileName := file.Name()
	_, err = file.Write(buffer)
	if err != nil {
		file.Close()
		return "", err
	}

	err = file.Sync()
	if err != nil {
		file.Close()
		return "", err
	}

	err = file.Close()
	if err != nil {
		return "", err
	}

	err = os.Rename(temporaryFileName, blobPath)
	if err != nil {
		os.Remove(temporaryFileName)
		return "", err
	}

	return key, nil
}
