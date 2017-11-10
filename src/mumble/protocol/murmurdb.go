package protocol

// This file implements a Server that can be created from a Murmur SQLite file.
// This is read-only, so it's not generally useful.  It's meant as a convenient
// way to import a Murmur server into Grumble, to be able to dump the structure of the
// SQLite datbase into a format that Grumble can understand.

import (
	"database/sql"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

const (
	ChannelInfoDescription int = iota
	ChannelInfoPosition
)

const (
	UserInfoName int = iota
	UserInfoEmail
	UserInfoComment
	UserInfoHash
	UserInfoPassword
	UserInfoLastActive
)

const SQLiteSupport = true

// Import the structure of an existing Murmur SQLite database.
func MurmurImport(filename string) (err error) {
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		panic(err.Error())
	}

	rows, err := db.Query("SELECT server_id FROM servers")
	if err != nil {
		panic(err.Error())
	}

	// TODO: Use a standardized struct not local inline variables randomly initialized in massive fucns
	var serverIDs []uint32
	var sid uint32
	for rows.Next() {
		err = rows.Scan(&sid)
		if err != nil {
			return err
		}
		serverIDs = append(serverIDs, sid)
	}

	log.Printf("Found servers: %v (%v servers)", serverIDs, len(serverIDs))

	for _, sid := range serverIDs {
		m, err := NewServerFromSQLite(sid, db)
		if err != nil {
			return err
		}

		// TODO: Confine like logic, Args should ONLY be in the command files, rest should rely on configuration created or defined by command execution
		// TODO: Grab a server and use the servers configuration file to know where to pullf rom
		err = os.Mkdir(filepath.Join(strconv.FormatUint(uint64(sid), 10)), 0750)
		if err != nil {
			return err
		}

		// TODO: Freeze to file is better said as write to file, also use a lib
		//err = m.FreezeToFile()
		//if err != nil {
		//	return err
		//}

		log.Printf("Successfully imported server %v", sid)
	}

	return
}

// Create a new Server from a Murmur SQLite database
func NewServerFromSQLite(id uint32, db *sql.DB) (server *Server, err error) {
	server, err = NewServer(id)
	if err != nil {
		return nil, err
	}

	// TODO: If you pass server, there should ZERO reason to pass a specific attribute of the server afterwards
	err = populateChannelInfoFromDatabase(server, server.RootChannel(), db)
	if err != nil {
		return nil, err
	}

	err = populateChannelACLFromDatabase(server, server.RootChannel(), db)
	if err != nil {
		return nil, err
	}

	err = populateChannelGroupsFromDatabase(server, server.RootChannel(), db)
	if err != nil {
		return nil, err
	}

	err = populateChannelsFromDatabase(server, db, 0)
	if err != nil {
		return nil, err
	}

	err = populateChannelLinkInfo(server, db)
	if err != nil {
		return nil, err
	}

	err = populateUsers(server, db)
	if err != nil {
		return nil, err
	}

	err = populateBans(server, db)
	if err != nil {
		return nil, err
	}

	return
}

// Add channel metadata (channel_info table from SQLite) by reading the SQLite database.
func populateChannelInfoFromDatabase(server *Server, channel *Channel, db *sql.DB) error {
	// TODO: What is the stmt mean? thats confusing variable naming
	sqlStatement, err := db.Prepare("SELECT value FROM channel_info WHERE server_id=? AND channel_id=? AND key=?")
	if err != nil {
		return err
	}

	// Fetch description
	rows, err := sqlStatement.Query(server.ID, channel.ID, ChannelInfoDescription)
	if err != nil {
		return err
	}
	for rows.Next() {
		var description string
		err = rows.Scan(&description)
		if err != nil {
			return err
		}

		if len(description) > 0 {
			// TODO: Fix this after structural changes, just use a fucking embedded db
			//key, err := blobStore.Put([]byte(description))
			//if err != nil {
			//	return err
			//}
			//channel.DescriptionBlob = key
		}
	}

	// Fetch position
	rows, err = sqlStatement.Query(server.ID, channel.ID, ChannelInfoPosition)
	if err != nil {
		return err
	}
	for rows.Next() {
		var position int
		if err := rows.Scan(&position); err != nil {
			return err
		}

		// TODO: Why not just assing it directly?
		channel.Position = position
	}

	return nil
}

// Populate channel with its ACLs by reading the SQLite databse.
func populateChannelACLFromDatabase(server *Server, channel *Channel, db *sql.DB) error {
	sqlStatement, err := db.Prepare("SELECT user_id, group_name, apply_here, apply_sub, grantpriv, revokepriv FROM acl WHERE server_id=? AND channel_id=? ORDER BY priority")
	if err != nil {
		return err
	}

	rows, err := sqlStatement.Query(server.ID, channel.ID)
	if err != nil {
		return err
	}

	for rows.Next() {
		// TODO: Use structs, not local variables that are inited half way through a massive func, becomes undebuggable mess quickly
		var (
			UserID    string
			Group     string
			ApplyHere bool
			ApplySub  bool
			Allow     int64
			Deny      int64
		)
		if err := rows.Scan(&UserID, &Group, &ApplyHere, &ApplySub, &Allow, &Deny); err != nil {
			return err
		}

		// TODO: Fix this ACL shit later once we have an embedded db and the structure is fixed
		//ACLEntry := ACL{}
		//ACLEntry.ApplyHere = ApplyHere
		//ACLEntry.ApplySubs = ApplySub
		//// TODO: validations get their own functions for code reuse, and counting entire UserID is not necessary to check if empty
		//if len(UserID) > 0 {
		//	ACLEntry.UserID, err = strconv.Atoi(UserID)
		//	if err != nil {
		//		return err
		//	}
		//} else if len(Group) > 0 {
		//	ACLEntry.Group = Group
		//} else {
		//	return errors.New("Invalid ACL: Neither Group or UserID specified")
		//}

		//ACLEntry.Deny = Permission(Deny)
		//ACLEntry.Allow = Permission(Allow)
		//// TODO: Really hate this ACL.ACLs, should be better
		//channel.ACL.ACLs = append(channel.ACL.ACLs, ACLEntry)
	}

	return nil
}

// Populate channel with groups by reading the SQLite database.
func populateChannelGroupsFromDatabase(server *Server, channel *Channel, db *sql.DB) error {
	sqlStatement, err := db.Prepare("SELECT group_id, name, inherit, inheritable FROM groups WHERE server_id=? AND channel_id=?")
	if err != nil {
		return err
	}

	rows, err := sqlStatement.Query(server.ID, channel.ID)
	if err != nil {
		return err
	}

	groups := make(map[uint32]Group)

	for rows.Next() {
		var (
			GroupID     uint32
			Name        string
			Inherit     bool
			Inheritable bool
		)

		if err := rows.Scan(&GroupID, &Name, &Inherit, &Inheritable); err != nil {
			return err
		}

		group := NewGroup(Name)
		group.Inherit = Inherit
		group.Inheritable = Inheritable
		//channel.ACL.Groups[group.Name] = group
		groups[GroupID] = group
	}

	// TODO: If there are patterns, modularize and fragment with functions!
	sqlStatement, err = db.Prepare("SELECT user_id, addit FROM group_members WHERE server_id=? AND group_id=?")
	if err != nil {
		return err
	}

	for gid, group := range groups {
		rows, err = sqlStatement.Query(server.ID, gid)
		if err != nil {
			return err
		}

		for rows.Next() {
			// TODO: Use a struct!
			var (
				UserID uint32
				Add    bool
			)

			if err := rows.Scan(&UserID, &Add); err != nil {
				return err
			}

			if Add {
				group.Add[UserID] = true
			} else {
				group.Remove[UserID] = true
			}
		}
	}

	return nil
}

// Populate the Server with Channels from the database.
func populateChannelsFromDatabase(server *Server, db *sql.DB, parentID uint32) error {
	parentChannel, exists := server.Channels[parentID]
	if !exists {
		return errors.New("Non-existant parent")
	}

	sqlStatement, err := db.Prepare("SELECT channel_id, name, inheritacl FROM channels WHERE server_id=? AND parent_id=?")
	if err != nil {
		return err
	}

	rows, err := sqlStatement.Query(server.ID, parentID)
	if err != nil {
		return err
	}

	for rows.Next() {
		// TODO: Use a struct plz
		var (
			name      string
			channelID uint32
			inherit   bool
		)
		err = rows.Scan(&channelID, &name, &inherit)
		if err != nil {
			return err
		}

		channel := NewChannel(channelID, name)
		server.Channels[channel.ID] = channel
		// TODO: Repair after fixing ACL system with embedded db
		//channel.ACL.InheritACL = inherit
		parentChannel.AddChild(channel)
	}

	// Add channel_info
	for _, childChannel := range parentChannel.children {
		err = populateChannelInfoFromDatabase(server, childChannel, db)
		if err != nil {
			return err
		}
	}

	// Add ACLs
	for _, childChannel := range parentChannel.children {
		err = populateChannelACLFromDatabase(server, childChannel, db)
		if err != nil {
			return err
		}
	}

	// Add groups
	for _, childChannel := range parentChannel.children {
		err = populateChannelGroupsFromDatabase(server, childChannel, db)
		if err != nil {
			return err
		}
	}

	// Add subchannels
	for id, _ := range parentChannel.children {
		err = populateChannelsFromDatabase(server, db, id)
		if err != nil {
			return err
		}
	}

	return nil
}

// Link a Server's channels together
func populateChannelLinkInfo(server *Server, db *sql.DB) (err error) {
	sqlStatement, err := db.Prepare("SELECT channel_id, link_id FROM channel_links WHERE server_id=?")
	if err != nil {
		return err
	}

	rows, err := sqlStatement.Query(server.ID)
	if err != nil {
		return err
	}

	for rows.Next() {
		// TODO: Use structs stop wasting memory with inline local variables that are not even being actively unallacated
		var (
			ChannelID uint32
			LinkID    uint32
		)
		if err := rows.Scan(&ChannelID, &LinkID); err != nil {
			return err
		}

		channel, exists := server.Channels[ChannelID]
		if !exists {
			return errors.New("Attempt to perform link operation on non-existant channel.")
		}

		other, exists := server.Channels[LinkID]
		if !exists {
			return errors.New("Attempt to perform link operation on non-existant channel.")
		}

		server.LinkChannels(channel, other)
	}

	return nil
}

func populateUsers(server *Server, db *sql.DB) (err error) {
	// Populate the server with regular user data
	sqlStatement, err := db.Prepare("SELECT user_id, name, pw, lastchannel, texture, strftime('%s', last_active) FROM users WHERE server_id=?")
	if err != nil {
		return
	}

	rows, err := sqlStatement.Query(server.ID)
	if err != nil {
		return
	}

	for rows.Next() {
		var (
			UserID   uint32
			UserName string
			// TODO: 2017 we dont use easily broken hashes like SHA1 bitte bitte bitte
			SHA1Password string
			LastChannel  uint32
			Texture      []byte
			LastActive   uint64
		)

		err = rows.Scan(&UserID, &UserName, &SHA1Password, &LastChannel, &Texture, &LastActive)
		if err != nil {
			continue
		}

		if UserID == 0 {
			// TODO: We can do better, 2017, dont use sha1
			server.config.Set("SuperUserPassword", "sha1$$"+SHA1Password)
		}

		user, err := NewUser(UserID, UserName)
		if err != nil {
			return err
		}

		if len(Texture) > 0 {
			// TODO: Update blobstore after a embedded db is up
			//key, err := blobStore.Put(Texture)
			//if err != nil {
			//	return err
			//}
			//user.TextureBlob = key
		}

		// TODO: Why does this need to be typecast? Why not just have the LastActive attribute be that type?
		user.LastActive = uint64(LastActive)
		user.LastChannelID = LastChannel

		server.Users[user.ID] = user
	}

	sqlStatement, err = db.Prepare("SELECT key, value FROM user_info WHERE server_id=? AND user_id=?")
	if err != nil {
		return
	}

	// Populate users with any new-style UserInfo records
	for uid, user := range server.Users {
		rows, err = sqlStatement.Query(server.ID, uid)
		if err != nil {
			return err
		}

		for rows.Next() {
			var (
				Key   int
				Value string
			)

			err = rows.Scan(&Key, &Value)
			if err != nil {
				return err
			}

			switch Key {
			case UserInfoEmail:
				user.Email = Value
			case UserInfoComment:
				// TODO: Fix blobstore after first wave refactor
				//key, err := blobStore.Put([]byte(Value))
				//if err != nil {
				//	return err
				//}
				//user.CommentBlob = key
			case UserInfoHash:
				// TODO: So why Certificate over Cert? Because there are other words with the Cert base that could possibly/reasonably work
				user.CertificateHash = Value
			case UserInfoLastActive:
				// not a kv-pair (trigger)
			case UserInfoPassword:
				// not a kv-pair
			case UserInfoName:
				// not a kv-pair
			}
		}
	}
	return
}

// Populate bans
func populateBans(server *Server, db *sql.DB) (err error) {
	sqlStatement, err := db.Prepare("SELECT base, mask, name, hash, reason, start, duration FROM bans WHERE server_id=?")
	if err != nil {
		return
	}

	rows, err := sqlStatement.Query(server.ID)
	if err != nil {
		return err
	}

	for rows.Next() {
		// TODO: Use structs not inline local variables
		var (
			Ban       Ban
			IP        []byte
			StartDate string
			Duration  int64
		)

		err = rows.Scan(&IP, &Ban.Mask, &Ban.Username, &Ban.CertificateHash, &Ban.Reason, &StartDate, &Duration)
		if err != nil {
			return err
		}

		if len(IP) == 16 && IP[10] == 0xff && IP[11] == 0xff {
			Ban.IP = net.IPv4(IP[12], IP[13], IP[14], IP[15])
		} else {
			Ban.IP = IP
		}

		Ban.SetISOStartDate(StartDate)
		Ban.Duration = Duration

		server.Bans = append(server.Bans, Ban)
	}

	return
}
