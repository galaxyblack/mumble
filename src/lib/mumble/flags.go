package mumble

type Flag uint32

const (
	IgnoreMergeErrors Flag = 0x2
	IgnoreACLErrors   Flag = 0x4
)
