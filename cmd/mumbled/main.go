package main

import (
	"fmt"
	"os"
	"path/filepath"
	//"regexp"

	"lib/mumble"

	cli "github.com/urfave/cli"
)

// TODO:LIST
// 1) Switch out the Flags/CLI framework to simplify the command-line and add feature improvements
// 2) Switch out the builtin logging system implemented across several files/objects for a community built centralized logging solution
// 3) Switch out the file based and map system configuration system in favor of an embedded DB solution like BoltDB (will remove 40% of the code base, and simplify development/debugging)
// 4) Using the new systems convert the configuration system to using the embedded DB
// 5) Rebuild the server, client, acl and other objects using the embedded KV DB
// 6) Upgrade the SHA1 password hashing system for at least SHA256, better would be adding OTP, keypair based guest system with later registration

// At that point it should be ready for 0.1.0 alpha release

var err error

type Command struct {
	name     string
	config   mumble.Config
	dataPath string
	// TODO: Probably eventually define all commands and flags here
}

func main() {
	command := Command{
		name:     "mumbled",
		config:   mumble.Config{},
		dataPath: filepath.Join(os.Getenv("HOME"), ".local/config/mumbled"),
	}
	// TODO: It only makes sense to have multiple servers in the case we are clustering and managing either multiple servers locally or both locally and remotely. This is fine but the functionality was never present in grumble, so for now it would be fine to leave this but all other server logic or even clustering logic should be in appropriate server.go or cluster.go files
	// TODO: Also all this would be better in embedded DB not a map
	//servers := make(map[uint32]protocol.Server)

	// LIB:cli:command line tool framework
	// This is great because we can take out 50% of this file, giving us access to better features,
	// community updates and less code to manage. This lets us focus on writing mumble protocol specific code.
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "data",
			Value: command.dataPath,
			Usage: "The default " + command.name + " application data directory",
		},
		cli.StringFlag{
			Name:  "log",
			Value: (command.name + ".log"),
			Usage: "Filename of log file located in " + command.name + " data directory",
		},
		cli.StringFlag{
			Name:  "config",
			Value: (command.name + ".yaml"),
			Usage: "Filename of config file located in " + command.name + " data directory",
		},
	}

	// [ Below values potentially can be loaded from a build config, perhaps have these be in gravity go build tool ]
	app.Name = command.name
	// # Args that should have been actions not flags
	//RegenKeys     bool - THIS SHOULD BE A FUCKING ACTION
	//SQLiteDB 			string
	//CleanUp  			bool
	app.Action = func(c *cli.Context) error {
		fmt.Println(command.name)
		fmt.Println("==========")
		fmt.Println("["+command.name+"] Data directory is currently set to: ", c.String("data"))
		fmt.Println("["+command.name+"] Log file name is currently set to: ", c.String("log"))
		fmt.Println("["+command.name+"] Config file name is currently set to: ", c.String("config"))

		// Input Arguments
		// - Input Validation
		// If not default value, validate not empty
		if c.String("data") == "" {

		}
		// If not default value, validate path format

		if c.NArg() > 0 {
			firstArg := c.Args().Get(0)
			fmt.Println("First arg is : ", firstArg)
		}

		// Config
		// In order of: flags > env > default value

		// If flag exist it is top priority, so continue

		// else
		//  Env exist? it is top priority so continue
		//  else
		//    default value set and continue

		// Application Data Directory
		if _, err := os.Stat(c.String("data")); os.IsNotExist(err) {
			os.Mkdir(c.String("data"), 600)
		}
		return nil
	}
	app.Run(os.Args)

	// If the defined dataDirectory does not exist? Make it

	//dataDirectory, err := os.Open(Args.DataDirectory)
	//if err != nil {
	//	// TODO: Perhaps just create the folder instead of erroring out?
	//	// Well this should be impossible now
	//	log.Fatalf("Unable to open data directory: %v", err)
	//	return
	//}
	//dataDirectory.Close()

	//// Set up logging
	//// TODO: No thanks, lets just use a lib, its not terrible but it could be much better
	////err = logTarget.Target.OpenFile(Args.LogPath)
	////if err != nil {
	////	fmt.Fprintf(os.Stderr, "Unable to open log file: %v", err)
	////	return
	////}
	////log.SetPrefix("[M] ")
	////log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	////log.SetOutput(&logTarget.Target)
	////log.Printf("Mumble")
	////log.Printf("Using data directory: %s", Args.DataDirectory)

	//// Open the blobStore.  If the directory doesn't
	//// already exist, create the directory and open
	//// the blobStore.
	//// The Open method of the blobstore performs simple
	//// sanity checking of content of the blob directory,
	//// and will return an error if something's amiss.

	//// Check whether we should regenerate the default global keypair
	//// and corresponding certificate.
	//// These are used as the default certificate of all virtual servers
	//// and the SSH admin console, but can be overridden using the "key"
	//// and "cert" arguments to Grumble.
	//// TODO: Move this into a certificate.go file, no need to implement that in the command-line file.
	//certificateFilename := filepath.Join(Args.DataDirectory, "cert.pem")
	//keyFilename := filepath.Join(Args.DataDirectory, "key.pem")
	//shouldRegen := false
	//if Args.RegenKeys {
	//	shouldRegen = true
	//} else {
	//	// OK. Here's the idea:  We check for the existence of the cert.pem
	//	// and key.pem files in the data directory on launch. Although these
	//	// might be deleted later (and this check could be deemed useless),
	//	// it's simply here to be convenient for admins.
	//	hasKey := true
	//	hasCertificate := true
	//	_, err = os.Stat(certificateFilename)
	//	if err != nil && os.IsNotExist(err) {
	//		hasCertificate = false
	//	}
	//	_, err = os.Stat(keyFilename)
	//	if err != nil && os.IsNotExist(err) {
	//		hasKey = false
	//	}
	//	if !hasCertificate && !hasKey {
	//		shouldRegen = true
	//	} else if !hasCertificate || !hasKey {
	//		//# TODO: Probably should be using ACME/letsencrypt since there is a lot of
	//		//# iterations that dont even have dependencies
	//		if !hasCertificate {
	//			//log.Fatal("Mumble could not find its default certificate (cert.pem)")
	//		}
	//		if !hasKey {
	//			//log.Fatal("Mumble could not find its default private key (key.pem)")
	//		}
	//	}
	//}
	//if shouldRegen {
	//	//log.Printf("Generating 4096-bit RSA keypair for self-signed certificate...")

	//	// TODO: Just fix this later
	//	//err := GenerateSelfSignedCertificate(certificateFilename, keyFilename)
	//	//if err != nil {
	//	//	log.Printf("Error: %v", err)
	//	//	return
	//	//}

	//	//log.Printf("Certificate output to %v", certificateFilename)
	//	//log.Printf("Private key output to %v", keyFilename)
	//}

	//// TODO: Deal with this later
	//// Should we import data from a Murmur SQLite file?
	////if SQLiteSupport && len(Args.SQLiteDB) > 0 {
	////	directory, err := os.Open(Args.DataDirectory)
	////	if err != nil {
	////		log.Fatalf("Murmur import failed: %s", err.Error())
	////	}
	////	defer directory.Close()

	////	names, err := directory.Readdirnames(-1)
	////	if err != nil {
	////		log.Fatalf("Murmur import failed: %s", err.Error())
	////	}

	////	// TODO: don't bother counting past 1 if you only want to know if its greater than 1
	////	if !Args.CleanUp && len(names) > 0 {
	////		log.Fatalf("Non-empty datadir. Refusing to import Murmur data.")
	////	}
	////	if Args.CleanUp {
	////		log.Print("Cleaning up existing data directory")
	////		for _, name := range names {
	////			if err := os.RemoveAll(filepath.Join(Args.DataDirectory, name)); err != nil {
	////				log.Fatalf("Unable to cleanup file: %s", name)
	////			}
	////		}
	////	}

	////	log.Printf("Importing Murmur data from '%s'", Args.SQLiteDB)
	////	if err = MurmurImport(Args.SQLiteDB); err != nil {
	////		log.Fatalf("Murmur import failed: %s", err.Error())
	////	}

	////	log.Printf("Import from Murmur SQLite database succeeded.")
	////	log.Printf("Please restart Mumble to make use of the imported data.")

	////	return
	////}

	//// Create the servers directory if it doesn't already
	//// exist.
	//serversDirectoryPath := filepath.Join(Args.DataDirectory, "servers")
	//err = os.Mkdir(serversDirectoryPath, 0700)
	//if err != nil && !os.IsExist(err) {
	//	log.Fatalf("Unable to create servers directory: %v", err)
	//}

	//// Read all entries of the servers directory.
	//// We need these to load our virtual servers.
	//serversDirectory, err := os.Open(serversDirectoryPath)
	//if err != nil {
	//	log.Fatalf("Unable to open the servers directory: %v", err.Error())
	//}
	//names, err := serversDirectory.Readdirnames(-1)
	//if err != nil {
	//	log.Fatalf("Unable to read file from data directory: %v", err.Error())
	//}
	//// The data dir file descriptor.
	//err = serversDirectory.Close()
	//if err != nil {
	//	log.Fatalf("Unable to close data directory: %v", err.Error())
	//	return
	//}

	//// Look through the list of files in the data directory, and
	//// load all virtual servers from disk.
	//// TODO: is there really any advantage over the term freeze as opposed to the known term write to file?
	//// TODO: This is not right, int64 id? should be uint32, and why not just use an embedded DB
	//servers = make(map[uint32]protocol.Server)
	//for _, name := range names {
	//	if matched, _ := regexp.MatchString("^[0-9]+$", name); matched {
	//		log.Printf("Loading server %v", name)
	//		// TODO: Get rid of freezing, just use db to "freeze" config values
	//		//s, err := NewServerFromFrozen(name)
	//		//if err != nil {
	//		//	log.Fatalf("Unable to load server: %v", err.Error())
	//		//}
	//		//err = s.FreezeToFile()
	//		//if err != nil {
	//		//	log.Fatalf("Unable to freeze server to disk: %v", err.Error())
	//		//}
	//		//servers[s.ID] = s
	//	}
	//}

	//// If no servers were found, create the default virtual server.
	//// TODO: Only checking if at least 1 exist? then dont count over 1
	//if len(servers) == 0 {
	//	s, err := protocol.NewServer(1)
	//	if err != nil {
	//		log.Fatalf("Couldn't start server: %s", err.Error())
	//	}

	//	servers[s.ID] = s
	//	os.Mkdir(filepath.Join(serversDirectoryPath, fmt.Sprintf("%v", 1)), 0750)
	//	// TODO: Get rid of freeze concept
	//	//err = s.FreezeToFile()
	//	//if err != nil {
	//	//	log.Fatalf("Unable to freeze newly created server to disk: %v", err.Error())
	//	//}
	//}

	//// Launch the servers we found during launch...
	//for _, server := range servers {
	//	err = server.Start()
	//	if err != nil {
	//		log.Printf("Unable to start server %v: %v", server.ID, err.Error())
	//	}
	//}

	//// If any servers were loaded, launch the signal
	//// handler goroutine and sleep...
	//// TODO: Only checking if at least 1 exist? then dont count over 1
	//if len(servers) > 0 {
	//	go protocol.SignalHandler()
	//	select {}
	//}
}
