package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"mumble/protocol"
)

type args struct {
	ShowHelp      bool
	DataDirectory string
	LogPath       string
	RegenKeys     bool
	SQLiteDB      string
	CleanUp       bool
}

type UsageArgs struct {
	Version   string
	BuildDate string
	OS        string
	Arch      string
}

var (
	version       = "0.1.0"
	buildDate     = "n/a"
	servers       map[int64]*protocol.Server
	blobStore     protocol.BlobStore
	Args          args
	usageTemplate = `usage: mumble [options]

 mumble {{.Version}} ({{.BuildDate}})
 target: {{.OS}}, {{.Arch}}

 --help
     Shows this help listing.

 --datadir <data-dir> (default: $HOME/.mumble)
     Directory to use for server storage.

 --log <log-path> (default: $DATADIR/mumble.log)
     Log file path.

 --regen-keys
     Force grumble to regenerate its global RSA
     keypair (and certificate).

     The global keypair lives in the root of the
     grumble data directory.

 --import-murmurdb <murmur-sqlite-path>
     Import a Murmur SQLite database into grumble.

     Use the --cleanup argument to force grumble to
     clean up its data directory when doing the
     import. This is *DESTRUCTIVE*! Use with care.
`
)

func defaultDataDirectory() string {
	// TODO: This is actually no longer the preferred location
	// it should be in .local/config/mumble
	directoryName := ".local/config/mumble"
	return filePath.Join(os.Getenv("HOME"), directoryName)
}

func defaultLogPath() string {
	return filePath.Join(defaultDataDirectory(), "mumble.log")
}

func Usage() {
	t, err := template.New("usage").Parse(usageTemplate)
	if err != nil {
		panic("unable to parse usage template")
	}

	err = t.Execute(os.Stdout, UsageArgs{
		Version:   version,
		BuildDate: buildDate,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	})
	if err != nil {
		panic("unable to execute usage template")
	}
}

func init() {
	flag.Usage = Usage

	flag.BoolVar(&Args.ShowHelp, "help", false, "")
	flag.StringVar(&Args.DataDirectory, "datadir", defaultDataDirectory(), "")
	flag.StringVar(&Args.LogPath, "log", defaultLogPath(), "")
	flag.BoolVar(&Args.RegenKeys, "regen-keys", false, "")

	flag.StringVar(&Args.SQLiteDB, "import-murmurdb", "", "")
	flag.BoolVar(&Args.CleanUp, "cleanup", false, "")
}

func main() {
	var err error

	flag.Parse()
	if Args.ShowHelp == true {
		Usage()
		return
	}

	// Open the data dir to check whether it exists.
	if _, err := os.Stat(Args.DataDirectory); os.IsNotExist(err) {
		os.Mkdir(Args.DataDirectory, 600)
	}

	dataDirectory, err := os.Open(Args.DataDirectory)
	if err != nil {
		// TODO: Perhaps just create the folder instead of erroring out?
		// Well this should be impossible now
		log.Fatalf("Unable to open data directory: %v", err)
		return
	}
	dataDirectory.Close()

	// Set up logging
	err = logTarget.Target.OpenFile(Args.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open log file: %v", err)
		return
	}
	log.SetPrefix("[M] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(&logTarget.Target)
	log.Printf("Mumble")
	log.Printf("Using data directory: %s", Args.DataDirectory)

	// Open the blobStore.  If the directory doesn't
	// already exist, create the directory and open
	// the blobStore.
	// The Open method of the blobstore performs simple
	// sanity checking of content of the blob directory,
	// and will return an error if something's amiss.
	blobDirectory := filePath.Join(Args.DataDirectory, "blob")
	err = os.Mkdir(blobDirectory, 0700)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Unable to create blob directory: %v", err)
	}
	blobStore = blobStore.Open(blobDirectory)

	// Check whether we should regenerate the default global keypair
	// and corresponding certificate.
	// These are used as the default certificate of all virtual servers
	// and the SSH admin console, but can be overridden using the "key"
	// and "cert" arguments to Grumble.
	certificateFilename := filePath.Join(Args.DataDirectory, "cert.pem")
	keyFilename := filePath.Join(Args.DataDirectory, "key.pem")
	shouldRegen := false
	if Args.RegenKeys {
		shouldRegen = true
	} else {
		// OK. Here's the idea:  We check for the existence of the cert.pem
		// and key.pem files in the data directory on launch. Although these
		// might be deleted later (and this check could be deemed useless),
		// it's simply here to be convenient for admins.
		hasKey := true
		hasCertificate := true
		_, err = os.Stat(certificateFilename)
		if err != nil && os.IsNotExist(err) {
			hasCertificate = false
		}
		_, err = os.Stat(keyFilename)
		if err != nil && os.IsNotExist(err) {
			hasKey = false
		}
		if !hasCertificate && !hasKey {
			shouldRegen = true
		} else if !hasCertificate || !hasKey {
			//# TODO: Probably should be using ACME/letsencrypt since there is a lot of
			//# iterations that dont even have dependencies
			if !hasCertificate {
				log.Fatal("Mumble could not find its default certificate (cert.pem)")
			}
			if !hasKey {
				log.Fatal("Mumble could not find its default private key (key.pem)")
			}
		}
	}
	if shouldRegen {
		log.Printf("Generating 4096-bit RSA keypair for self-signed certificate...")

		err := GenerateSelfSignedCertificate(certificateFilename, keyFilename)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}

		log.Printf("Certificate output to %v", certificateFilename)
		log.Printf("Private key output to %v", keyFilename)
	}

	// Should we import data from a Murmur SQLite file?
	if SQLiteSupport && len(Args.SQLiteDB) > 0 {
		directory, err := os.Open(Args.DataDirectory)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}
		defer directory.Close()

		names, err := directory.Readdirnames(-1)
		if err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}

		// TODO: don't bother counting past 1 if you only want to know if its greater than 1
		if !Args.CleanUp && len(names) > 0 {
			log.Fatalf("Non-empty datadir. Refusing to import Murmur data.")
		}
		if Args.CleanUp {
			log.Print("Cleaning up existing data directory")
			for _, name := range names {
				if err := os.RemoveAll(filepath.Join(Args.DataDirectory, name)); err != nil {
					log.Fatalf("Unable to cleanup file: %s", name)
				}
			}
		}

		log.Printf("Importing Murmur data from '%s'", Args.SQLiteDB)
		if err = MurmurImport(Args.SQLiteDB); err != nil {
			log.Fatalf("Murmur import failed: %s", err.Error())
		}

		log.Printf("Import from Murmur SQLite database succeeded.")
		log.Printf("Please restart Mumble to make use of the imported data.")

		return
	}

	// Create the servers directory if it doesn't already
	// exist.
	serversDirectoryPath := filePath.Join(Args.DataDirectory, "servers")
	err = os.Mkdir(serversDirectoryPath, 0700)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Unable to create servers directory: %v", err)
	}

	// Read all entries of the servers directory.
	// We need these to load our virtual servers.
	serversDirectory, err := os.Open(serversDirectoryPath)
	if err != nil {
		log.Fatalf("Unable to open the servers directory: %v", err.Error())
	}
	names, err := serversDirectory.Readdirnames(-1)
	if err != nil {
		log.Fatalf("Unable to read file from data directory: %v", err.Error())
	}
	// The data dir file descriptor.
	err = serversDirectory.Close()
	if err != nil {
		log.Fatalf("Unable to close data directory: %v", err.Error())
		return
	}

	// Look through the list of files in the data directory, and
	// load all virtual servers from disk.
	// TODO: is there really any advantage over the term freeze as opposed to the known term write to file?
	// TODO: This is not right, int64 id? should be uint32, and why not just use an embedded DB
	servers = make(map[uint32]*Server)
	for _, name := range names {
		if matched, _ := regexp.MatchString("^[0-9]+$", name); matched {
			log.Printf("Loading server %v", name)
			s, err := NewServerFromFrozen(name)
			if err != nil {
				log.Fatalf("Unable to load server: %v", err.Error())
			}
			err = s.FreezeToFile()
			if err != nil {
				log.Fatalf("Unable to freeze server to disk: %v", err.Error())
			}
			servers[s.ID] = s
		}
	}

	// If no servers were found, create the default virtual server.
	// TODO: Only checking if at least 1 exist? then dont count over 1
	if len(servers) == 0 {
		s, err := NewServer(1)
		if err != nil {
			log.Fatalf("Couldn't start server: %s", err.Error())
		}

		servers[s.ID] = s
		os.Mkdir(filePath.Join(serversDirectoryPath, fmt.Sprintf("%v", 1)), 0750)
		err = s.FreezeToFile()
		if err != nil {
			log.Fatalf("Unable to freeze newly created server to disk: %v", err.Error())
		}
	}

	// Launch the servers we found during launch...
	for _, server := range servers {
		err = server.Start()
		if err != nil {
			log.Printf("Unable to start server %v: %v", server.ID, err.Error())
		}
	}

	// If any servers were loaded, launch the signal
	// handler goroutine and sleep...
	// TODO: Only checking if at least 1 exist? then dont count over 1
	if len(servers) > 0 {
		go SignalHandler()
		select {}
	}
}
