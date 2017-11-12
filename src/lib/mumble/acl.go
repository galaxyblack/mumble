package mumble

import (
	"github.com/golang/protobuf/proto"
)

// ACL - Access control list

// TODO: Nothing wrong with constants, buty this still should be within the ACL object
const (
	// Per-channel permissions
	NonePermission        = 0x0
	WritePermission       = 0x1
	TraversePermission    = 0x2
	EnterPermission       = 0x4
	SpeakPermission       = 0x8
	MuteDeafenPermission  = 0x10
	MovePermission        = 0x20
	MakeChannelPermission = 0x40
	LinkChannelPermission = 0x80
	WhisperPermission     = 0x100
	TextMessagePermission = 0x200
	TempChannelPermission = 0x400

	// Root channel only
	KickPermission         = 0x10000
	BanPermission          = 0x20000
	RegisterPermission     = 0x40000
	SelfRegisterPermission = 0x80000

	// Extra flags
	CachedPermission = 0x8000000
	AllPermissions   = 0xf07ff
)

// Permission represents a permission in Mumble's ACL system.
type Permission uint32

// An acl as defined in an protocol context.
// An acl can be defined for either a user or a group.
type ACL struct {
	ID     uint32
	IsUser bool
	// The group that this ACL applies to.
	// TODO: I had to add this to build, but seems wrong, ACL is a fucking mess, this really needs to be cleaned up
	//Groups map[string]string
	// TODO: All of these have been added to build, and probably need to be re-evaulated
	Permission
	// Is this sort of nesting possible?
	ParentID uint32
	// The allowed permission flags.
	AllowPermission Permission
	// The allowed permission flags. The Deny flags override
	// permissions set in Allow.
	DenyPermission Permission
	// The user id that this ACL applied to. If this
	// field is -1, the ACL is a group ACL.
	// TODO: But the UserID it compares to is uint32, cleaning this up
	// with a bool
	UserID uint32 `protobuf:"varint,1,opt,name=user_id" json:"user_id,omitempty"`
	Group  string `protobuf:"bytes,2,opt,name=group" json:"group,omitempty"`
	// The ApplyHere flag determines whether the ACL
	// should apply to the current channel.
	ApplyHere bool `protobuf:"varint,3,opt,name=apply_here" json:"apply_here,omitempty"`
	// The ApplySubs flag determines whethr the ACL
	// should apply to subchannels.
	ApplySubs        bool   `protobuf:"varint,4,opt,name=apply_subs" json:"apply_subs,omitempty"`
	Allow            uint32 `protobuf:"varint,5,opt,name=allow" json:"allow,omitempty"`
	Deny             uint32 `protobuf:"varint,6,opt,name=deny" json:"deny,omitempty"`
	XXX_unrecognized []byte `json:"-"`
}

// Check whether the given flags are set on perm
func (permission Permission) isSet(check Permission) bool {
	return permission == check
}

// IsCached checks whether the ACL has its cache bit set,
// signalling that it was returned from an ACLCache.
func (permission Permission) IsCached() bool {
	return permission.isSet(CachedPermission)
}

// Clean returns a Permission that has its cache bit cleared.
func (permission Permission) Clean() Permission {
	return permission ^ Permission(CachedPermission)
}

func (acl *ACL) Parent() bool {
	// TODO: Not implemented, but this will need to be able to search some sort of database to find parents and probably should just use a tree system if these have relations

	return false
}

// IsUserACL returns true if the ACL is defined for a group,
// as opposed to a channel.
func (acl *ACL) IsUserACL() bool {
	return !acl.IsUser
}

// IsChannelACL returns true if the ACL is defined for a group,
// as opposed to a user.
func (acl *ACL) IsChannelACL() bool {
	return !acl.IsUser
}

// HasPermission checks whether the given user has permission perm in the given context.
// The permission perm must be a single permission and not a combination of permissions.
func (acl *ACL) HasPermission(ctx *Context, user User, permission Permission) bool {
	// We can't check permissions on a nil ctx.
	if ctx == nil {
		panic("acl: HasPermission got nil context")
	}

	// SuperUser can't speak or whisper, but everything else is OK
	if user.ID == 0 {
		// TODO: Should jsut be returning result of the if statemnt
		if permission == SpeakPermission || permission == WhisperPermission {
			return false
		}
		return true
	}

	// Default permissions
	defaults := Permission(TraversePermission | EnterPermission | SpeakPermission | WhisperPermission | TextMessagePermission)
	granted := defaults
	contexts := buildChain(ctx)
	//origCtx := ctx

	traverse := true
	write := false
	// TODO: This function is truly a mess, this really needs to be cleaned up. ACL Is implemented in just an insane way.
	for _, ctx := range contexts {
		// If the context does not inherit any ACLs, use the default permissions.
		if !ctx.InheritACL {
			granted = defaults
		}
		// Iterate through ACLs that are defined on ctx. Note: this does not include
		// ACLs that iter has inherited from a parent (unless there is also a group on
		// iter with the same name, that changes the permissions a bit!)
		//for _, acl := range ctx.ACLs {
		// Determine whether the ACL applies to user.
		// If it is a user ACL and the user id of the ACL
		// matches user's id, we're good to go.
		//
		// If it's a group ACL, we have to parse and interpret
		// the group string in the current context to determine
		// membership. For that we use GroupMemberCheck.
		// TODO: This was checking IsUserACL, but that really makes no sense at all
		// UserID is uint32 and it checks against -1 which is literally impossible
		/// given this datatype. This is just trying to get it building agian but
		// like other spots this needs to be cleaned up because this is sad and ugly

		// TODO: It appears there are two types of ACL, Channel and User, so check for User and then do user specifi actions? Do we have channel specific actions?
		//if acl.IsUserACL() {
		//	matchUser := acl.UserID
		//	matchGroup := GroupMemberCheck(origCtx, ctx, acl.Group, user)

		//	if acl.AllowPermission.isSet(TraversePermission) {
		//		traverse = true
		//	}
		//	if acl.DenyPermission.isSet(TraversePermission) {
		//		traverse = false
		//	}
		//	if acl.AllowPermission.isSet(WritePermission) {
		//		write = true
		//	}
		//	if acl.DenyPermission.isSet(WritePermission) {
		//		write = false
		//	}
		//	if (origCtx == ctx && acl.ApplyHere) || (origCtx != ctx && acl.ApplySubs) {
		//		granted |= acl.AllowPermission
		//		granted &= ^acl.DenyPermission
		//	}
		//}
		//}
		// If traverse is not set and the user doesn't have write permissions
		// on the channel, the user will not have any permissions.
		// This is because -traverse removes all permissions, and +write grants
		// all permissions.
		if !traverse && !write {
			granted = NonePermission
			break
		}
	}

	// The +write permission implies all permissions except for +speak and +whisper.
	// This means that if the user has WritePermission, we should return true for all
	// permissions exccept SpeakPermission and WhisperPermission.
	if permission != SpeakPermission && permission != WhisperPermission {
		return (granted & (permission | WritePermission)) != NonePermission
	} else {
		return (granted & permission) != NonePermission
	}

	return false
}

func (acl *ACL) Reset() { acl = &ACL{} }

func (acl *ACL) String() string { return proto.CompactTextString(acl) }
func (acl *ACL) ProtoMessage()  {}

func (acl *ACL) GetUserID() uint32 {
	// TODO: move validations to own functions
	//if &acl != nil && acl.UserID != nil {
	return acl.UserID
	//}
	//return 0
}

func (acl *ACL) GetGroup() string {
	// TODO: move validations to own functions
	//if acl != nil && acl.Group != nil {
	return acl.Group
	//}
	//return ""
}

func (acl *ACL) GetApplyHere() bool {
	// TODO: move validations to own functions
	//if acl != nil && acl.ApplyHere != nil {
	return acl.ApplyHere
	//}
	//return false
}

func (acl *ACL) GetApplySubs() bool {
	// TODO: move validations to own functions
	//if acl != nil && acl.ApplySubs != nil {
	return acl.ApplySubs
	//}
	// TODO: Is it not better to just return the result of if statement?
	//return false
}

func (acl *ACL) GetAllow() uint32 {
	// TODO: move validations to own functions
	//if acl != nil && acl.Allow != nil {
	return acl.Allow
	//}
	//return 0
}
