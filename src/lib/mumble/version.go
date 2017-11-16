package mumble

import (
	"strconv"
)

type Version struct {
	Major uint8
	Minor uint8
	Patch uint8
}

func (version Version) ToString() string {
	return (strconv.Itoa(int(version.Major)) + "." + strconv.Itoa(int(version.Minor)) + "." + strconv.Itoa(int(version.Patch)))
}
