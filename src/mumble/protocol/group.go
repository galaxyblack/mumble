package protocol

import (
	"log"
	//"strconv"
	"strings"
)

// Group represents a Group in an Context.
type Group struct {
	// The name of this group
	Name string

	// The inherit flag means that this group will inherit group
	// members from its parent.
	Inherit bool

	// The inheritable flag means that subchannels can
	// inherit the members of this group.
	Inheritable bool

	// TODO: Seems way excessive
	// Group adds permissions to these users
	Add map[uint32]bool
	// Group removes permissions from these users
	Remove map[uint32]bool
	// Temporary add (authenticators)
	Temporary map[uint32]bool
}

// EmptyGroupWithName creates a new Group with the given name.
// TODO: Didn't intiailize the function return variable why create one?
// TODO: The convention is NewGroup, thats what literally EVERY other file used
func NewGroup(name string) Group {
	// TODO: Check if name is nil or empty, then set a default or random one to avoid erroring unnecessarily
	return Group{
		Name:      name,
		Add:       make(map[uint32]bool),
		Remove:    make(map[uint32]bool),
		Temporary: make(map[uint32]bool),
	}
}

// AddContains checks whether the Add set contains id.
func (group *Group) AddContains(id uint32) (ok bool) {
	// TODO: Get rid of ok, not useful, use errors!
	_, ok = group.Add[id]
	return
}

// AddUsers gets the list of user ids in the Add set.
func (group *Group) AddUsers() []uint32 {
	// TODO: This is not a slice of users actually, its a slice of userIDs
	users := []uint32{}
	for uid, _ := range group.Add {
		users = append(users, uid)
	}
	return users
}

// RemoveContains checks whether the Remove set contains id.
func (group *Group) RemoveContains(id uint32) (ok bool) {
	_, ok = group.Remove[id]
	return
}

// RemoveUsers gets the list of user ids in the Remove set.
func (group *Group) RemoveUsers() []uint32 {
	users := []uint32{}
	for uid, _ := range group.Remove {
		users = append(users, uid)
	}
	return users
}

// TemporaryContains checks whether the Temporary set contains id.
func (group *Group) TemporaryContains(id uint32) (ok bool) {
	_, ok = group.Temporary[id]
	return
}

// MembersInContext gets the set of user id's from the group in the given context.
// This includes group members that have been inherited from an ancestor context.
func (group *Group) MembersInContext(context *Context) map[uint32]bool {
	groups := []Group{}
	members := map[uint32]bool{}

	// Walk a group's context chain, starting with the context the group
	// is defined on, followed by its parent contexts.
	// TODO: Whats the point of just recreating the same variable? Just wastes resources
	originalContext := context
	// TODO: This is a validation, needs own function
	for context != nil {
		currentGroup, ok := context.Groups[group.Name]
		// TODO: ok is useless for debugging and everyone who sues the server app
		if ok {
			// If the group is not inheritable, and we're looking at an
			// ancestor group, we've looked in all the groups we should.
			// TODO: Doesn't work can't use *Context against bool
			//if context != originalContext && !currentGroup.Inheritable {
			//	break
			//}
			// TODO: Find the current group and add it to the groups? What the fuck are we doing?

			// Add the group to the list of groups to be considered
			// If this group does not inherit from groups in its ancestors, stop looking
			// for more ancestor groups.
			// Comparing a *Context with bool, wont work
			//if !currentGroup.Inherit {
			//	break
			//}
		}
		// and why?
		context = context.Parent
	}

	// TODO: use embedded key/value store and simplify this software
	for _, currentGroup := range groups {
		for uid, _ := range currentGroup.Add {
			members[uid] = true
		}
		for uid, _ := range currentGroup.Remove {
			delete(members, uid)
		}
	}

	return members
}

// GroupMemberCheck checks whether a user is a member
// of the group as defined in the given context.
//
// The 'current' context is the context that group
// membership is currently being evaluated for.
//
// The 'acl' context is the context of the ACL that
// that group membership is being evaluated for.
//
// The acl context will always be either equal to
// current, or be an ancestor.
func GroupMemberCheck(current *Context, acl *Context, name string, user User) (ok bool) {
	// TODO: no, this is not right at all, usue a struct, or if you are going to hard code it, why not just know what it should be?
	valid := true
	invert := false
	token := false
	hash := false

	// Returns the 'correct' return value considering the value
	// of the invert flag.
	defer func() {
		if valid && invert {
			ok = !ok
		}
	}()

	channel := current

	for {
		// Empty group name are not valid.
		// TODO: Don't use len to check if string is empty, you count more than needed when its not
		if len(name) == 0 {
			// TODO: Return just valid then, dont set it then return false
			// and you can set the result of !if to valid and skip an if statement
			valid = false
			return valid
		}
		// Invert
		if name[0] == '!' {
			invert = true
			name = name[1:]
			continue
		}
		// Evaluate in ACL context (not current channel)
		if name[0] == '~' {
			channel = acl
			name = name[1:]
			continue
		}
		// Token
		if name[0] == '#' {
			token = true
			name = name[1:]
			continue
		}
		// Hash
		if name[0] == '$' {
			hash = true
			name = name[1:]
			continue
		}
		break
	}

	if token {
		// TODO: Validate token fomrat! dont get hacked by trusting input

		// The user is part of this group if the remaining name is part of
		// his access token list. The name check is case-insensitive.
		for _, token := range user.Tokens {
			if strings.ToLower(name) == strings.ToLower(token) {
				return true
			}
		}
		return false
	} else if hash {
		// The client is part of this group if the remaining name matches the
		// client's cert hash.
		if strings.ToLower(name) == strings.ToLower(user.CertificateHash) {
			// TODO: Again just return result of if statement
			return true
		}
		// TODO: Again just return result of if statement
		return false
	} else if name == "none" {
		// None
		// TODO: Again just return result of if statement
		return false
	} else if name == "all" {
		// Everyone
		// TODO: Again just return result of if statement
		return true
	} else if name == "auth" {
		// TODO: Again just return result of if statement
		// The user is part of the auth group is he is authenticated. That is,
		// his UserId is >= 0.
		// TODO: no, and should just be ID, you know its the user because thats the object, but really you are trying to check if the user is nil, and doing this way just causes so many stupid conversions on ID datatype
		return user.ID >= 0
	} else if name == "strong" {
		// The user is part of the strong group if he is authenticated to the server
		// via a strong certificate (i.e. non-self-signed, trusted by the server's
		// trusted set of root CAs).
		log.Printf("GroupMemberCheck: Implement strong certificate matching")
		return false
	} else if name == "in" {
		// Is the user in the currently evaluated channel?
		// TODO: Doesn't currently exist but probably a good fucntion to add eventually
		//return user.ACLContext() == channel
	} else if name == "out" {
		// Is the user not in the currently evaluated channel?
		// TODO: Nonexistent function, and if you are chcking someting against user, function should really be in the user
		//return user.ACLContext() != channel
	} else if name == "sub" {
		// TODO: Arguments should only be in command, this should only contain code related to group concept on server!
		// each of these ifs deserve a function with the name passed in
	} else {
		// Non-magic groups
		groups := []Group{}

		// TODO: Validate channel
		for channel != nil {
			// TODO: Use err not ok its useless!
			if group, ok := channel.Groups[name]; ok {
				// Skip non-inheritable groups if we're in parents
				// of our evaluated context.
				// TODO: Can't compare different data types, bool vs *COntent
				//if !group.Inheritable {
				//	break
				//}
				// Prepend group
				// TODO: Why?
				//groups = append([]Group{group}, groups...)
				// If this group does not inherit from groups in its ancestors, stop looking
				// for more ancestor groups.
				// This entire program could be cut in half by just using a proper embedded DB instead of trying to reimplemnt one
				//if !group.Inherit {
				//	break
				//}
			}
			// TODO: Validate parent exists!
			channel = channel.Parent
		}

		// TODO: No! Add to struct object
		isMember := false
		for _, group := range groups {
			// TODO: No use an embedded db stop recreating wheels
			//if group.AddContains(user.ID) || group.TemporaryContains(user.ID) || group.TemporaryContains(-int(user.Session())) {
			//	isMember = true
			//}
			if group.RemoveContains(user.ID) {
				isMember = false
			}
		}
		return isMember
	}

	return false
}

// Get the list of group names for the given ACL context.
//
// This function walks the through the context chain to figure
// out all groups that affect the given context whilst considering
// group inheritance.
func (context *Context) GroupNames() []string {
	names := map[string]bool{}
	originalContext := context
	contexts := []*Context{}

	// Walk through the whole context chain and all groups in it.
	// TODO: No just use a proper DB and simplify!
	//for _, context := range contexts {
	//	for _, group := range context.Groups {
	//		// A non-inheritable group in parent. Discard it.
	//		if context != originalContext && !group.Inheritable {
	//			delete(names, group.Name)
	//			// An inheritable group. Add it to the list.
	//		} else {
	//			names[group.Name] = true
	//		}
	//	}
	//}

	// Convert to slice
	// TODO: Do validations on names! Thats a security vulnerability! Just like paths, never trust any input ever!
	stringNames := make([]string, 0, len(names))
	for name, ok := range names {
		if ok {
			stringNames = append(stringNames, name)
		}
	}
	return stringNames
}
