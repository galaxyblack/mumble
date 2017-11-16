package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	//"regexp"

	"lib/mumble"
	"lib/uput/valid"

	db "github.com/tidwall/buntdb"
	cli "github.com/urfave/cli"
	//"github.com/urfave/cli/altsrc"
)

// TODO:LIST
// 1) Switch out the file based and map system configuration system in favor of an embedded DB solution like BoltDB (will remove 40% of the code base, and simplify development/debugging)
// 2) Switch out the builtin logging system implemented across several files/objects for a community built centralized logging solution
// 3) Using the new systems convert the configuration system to using the embedded DB
// 4) Rebuild the server, client, acl and other objects using the embedded KV DB
// 5) Upgrade the SHA1 password hashing system for at least SHA256, better would be adding OTP, keypair based guest system with later registration

// At that point it should be ready for 0.1.0 alpha release

type Locale struct {
	language string
	filetype string
	text     *db.DB
}

type Command struct {
	cache *db.DB // in memory buntdb
	// TODO: Support i18n, multiple language support from the beginning
	locale  Locale
	server  mumble.Server
	cluster []*mumble.Server
	// TODO: Probably eventually define all commands and flags here
}

// Command Print
func (command *Command) PrintBanner() {
	fmt.Println(command.server.Name + " " + command.server.Version.ToString())
	fmt.Println("=============")
}

func (command *Command) PrintNotImplemented() {
	fmt.Println("[DEBUGGING] Not implemented")
}

func (command *Command) PrintConfiguration() {
	fmt.Println("["+command.server.Name+"] Data directory is currently set to: ", command.server.Config.DataPath)
	fmt.Println("["+command.server.Name+"] Config file name is currently set to: ", command.server.Config.ConfigFile)
	fmt.Println("["+command.server.Name+"] Log file name is currently set to: ", command.server.Config.LogFile)
}

func main() {
	//var err error
	const commandName = "mumbled"
	// TODO: Support YAML, JSON, XML, and TOML formats
	// Default filetypes
	const configFiletype = "yaml"
	const localeFiletype = "yaml"
	const logFiletype = "json"

	cache, _ := db.Open(":memory:")
	textCache, _ := db.Open(":memory:")
	serverDB, _ := db.Open(":memory:")

	command := Command{
		cache: cache,
		locale: Locale{
			language: "en_GB",
			filetype: localeFiletype,
			text:     textCache,
		},
		server: mumble.Server{
			Name: commandName,
			DB:   serverDB,
			Config: mumble.Config{
				DataPath:   filepath.Join(os.Getenv("HOME"), ".local/config/", commandName),
				ConfigFile: (commandName + "." + configFiletype),
				LogFile:    (commandName + "." + logFiletype),
			},
			Version: mumble.Version{
				Major: 0,
				Minor: 0,
				Patch: 1,
			},
		},
	}
	command.PrintBanner()
	// LIB:cli:command line tool framework
	// This is great because we can take out 50% of this file, giving us access to better feature set,
	// community vetting, updates and less code to manage. Lets focus on writing mumble protocol specific code.
	app := cli.NewApp()
	app.Name = commandName
	app.Version = command.server.Version.ToString()
	// Flags
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "data, d",
			Value:  command.server.Config.DataPath,
			Usage:  (commandName + " application data directory `PATH`"),
			EnvVar: (strings.ToUpper(commandName) + "_DATA_PATH"),
		},
		cli.StringFlag{
			Name:     "log, l",
			Value:    (commandName + "." + logFiletype),
			Usage:    ("log to `FILE`"),
			EnvVar:   (strings.ToUpper(commandName) + "_LOG_FILE"),
			FilePath: command.server.Config.DataPath,
		},
		cli.StringFlag{
			Name:     "config, c",
			Value:    (commandName + "." + configFiletype),
			Usage:    ("load config from `FILE`"),
			EnvVar:   (strings.ToUpper(commandName) + "_CONFIG_FILE"),
			FilePath: command.server.Config.DataPath,
		},
		cli.StringFlag{
			Name:     "locale, lcl",
			Value:    (commandName + "." + localeFiletype),
			Usage:    ("load config from `FILE`"),
			EnvVar:   (strings.ToUpper(commandName) + "_CONFIG_FILE"),
			FilePath: command.server.Config.DataPath,
		},
		cli.BoolFlag{
			Name:   "debug, dbg",
			Usage:  ("print logs to stdout in addition to writing to log file"),
			EnvVar: (strings.ToUpper(commandName) + "_DEBUG"),
		},
	}
	// Commands
	// TODO: Technically these belong in mumble-cli but for now we will just implement it in the daemon, and break it out
	// only because we are refactoring and it is easier to rebuild logic within the same file
	app.Commands = []cli.Command{
		{
			Name:    "generate-keys",
			Aliases: []string{"genkey", "keygen", "kgen", "kg"},
			Usage:   "Generate new server keys",
			Action: func(c *cli.Context) error {
				// TODO: If exists, ask before overwriting
				fmt.Println("[Error] Not implemented")
				return nil
			},
		},
		{
			Name:    "generate-certificate",
			Aliases: []string{"certgen", "gencert", "cgen", "cg"},
			Usage:   "Generate new server TLS certificate",
			Action: func(c *cli.Context) error {
				// TODO: If exists ask before overwriting
				fmt.Println("[Error] Not implemented")
				return nil
			},
		},
		{
			Name:    "import-murmurdb",
			Aliases: []string{"importdb", "idb"},
			Usage:   "Import server database from existing murmur SQLite database",
			Action: func(c *cli.Context) error {
				// TODO: If exists ask before overwriting
				return nil
			},
		},
		{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Print the version",
			Action: func(c *cli.Context) error {
				// TODO: If exists ask before overwriting
				fmt.Println(commandName + " version " + command.server.Version.ToString())
				return nil
			},
		},
	}
	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	// Config File (YAML, TOML, JSON, XML)
	// "github.com/urfave/cli/altsrc"
	// altsrc.NewIntFlag(cli.IntFlag{Name: "test"})
	// YAML Example
	// command.Before = altsrc.InitInputSourceWithContext(command.Flags, NewYamlSourceFromFlagFunc("load"))
	app.Action = func(c *cli.Context) error {
		// Input
		// If c.String("data") is not default, it is overriding the default
		if c.String("data") != command.server.Config.DataPath {
			// + dataPath Input Validation
			fmt.Println("Default data path overriden by cli-framework data: ", c.String("data"))
			// VALIDATE:STRING: Not empty.

			//func (str string) IsEmpty() {
			//  fmt.Println("test")
			//}

			userInput, err := valid.IfString("test").IsUppercase().IsEmpty().IsValid()
			if err != nil {
				fmt.Println("userInput experienced an error: ", err)
			} else {
				fmt.Println("validated and usable userInput is:", userInput)
			}

			//fmt.Println("Is it empty? ", c.String("data").IsEmpty())

			// VALIDATE:STRING: Valid posix path format.
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
