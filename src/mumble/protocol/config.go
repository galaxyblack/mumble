package protocol

import (
	"strconv"
	"sync"
)

var defaultConfig = map[string]string{
	// TODO: Adding the arguments passed to the fucking program to the fucking config for fucks sake, sorry this is just getting absurdist
	"DataDir": "~/.local/config/mumble",
	//  TODO: Whats wrong with structs? Is this map really better? It could be a the built in attributes with a custom map for other values...and be way fucking faster, considering
	// these are probably checked, every time a user does anything?
	"MaxBandwidth":          "72000",
	"MaxUsers":              "1000",
	"MaxUsersPerChannel":    "0",
	"MaxTextMessageLength":  "5000",
	"MaxImageMessageLength": "131072",
	"AllowHTML":             "true",
	"DefaultChannel":        "0",
	"RememberChannel":       "true",
	// TODO: This should again be pulling from a build config for just a const with the name
	"WelcomeText": "Welcome to this server running <b>Mumble</b>.",
	"SendVersion": "true",
}

type Config struct {
	// TODO: Define some default values
	DataDirectory string // TODO: Only fucking one that should be a string!!!!
	// TODO: Should this be uint? Itd be much faster for comparisons, if we are going to do these comparisons all the time anyways
	MaxBandwidth       uint32
	MaxUsers           uint32
	MaxUsersPerChannel uint32
	// TODO: For fucks sake, we know this is checked every fucking message, and we are doing string comparison? Yep I've fucking lost it
	MaxTextMessageLength  uint32
	MaxImageMessageLength uint32
	AllowHTML             bool // TODO: Can we just use a bool? EVERY MESSAGE WE ARE CHECKING THIS? a bool as a string? for fucks sake
	// TODO: Just read above todos and apply below, right now I just want something to build and work, so fuck everything but seriously, this is awful design
	DefaultChannel       string
	RememberChannel      string
	WelcomeText          string
	SendVersion          bool
	customConfigurations map[string]string // TODO: I really prefer use a key value store but this is not terrible if we are talking about a few custom values
	// TODO: But keep in mind why use a string instead of a struct that lets the object be an int, uint, bool, and string for comparison so we dont wnat to slit our wrists and waste money and energy? there is a reason we didnt write this in JS
	configMap map[string]string
	mutex     sync.RWMutex
}

// Create a new Config using configMap as the intial internal config map.
// If configMap is nil, ConfigWithMap will create a new config map.
// TODO: Maybe attach this to server object?
func NewConfig(configMap map[string]string) *Config {
	if configMap == nil {
		configMap = make(map[string]string)
	}
	return &Config{configMap: configMap}
}

// Get a copy of the Config's internal config map
func (config *Config) GetAll() (all map[string]string) {
	config.mutex.RLock()
	defer config.mutex.RUnlock()

	all = make(map[string]string)
	for k, v := range config.configMap {
		all[k] = v
	}
	return
}

// Set a new value for a config key
func (config *Config) Set(key string, value string) {
	config.mutex.Lock()
	defer config.mutex.Unlock()
	config.configMap[key] = value
}

// Reset the value of a config key
func (config *Config) Reset(key string) {
	config.mutex.Lock()
	defer config.mutex.Unlock()
	delete(config.configMap, key)
}

// Get the value of a specific config key encoded as a string
func (config *Config) StringValue(key string) (value string) {
	config.mutex.RLock()
	defer config.mutex.RUnlock()

	value, exists := config.configMap[key]
	if exists {
		return value
	}

	value, exists = defaultConfig[key]
	if exists {
		return value
	}

	return ""
}

// Get the value of a speific config key as an int
func (config *Config) IntValue(key string) (intval int) {
	str := config.StringValue(key)
	intval, _ = strconv.Atoi(str)
	return
}

// Get the value of a specific config key as a uint32
func (config *Config) Uint32Value(key string) (uint32val uint32) {
	str := config.StringValue(key)
	uintval, _ := strconv.ParseUint(str, 10, 0)
	return uint32(uintval)
}

// Get the value fo a sepcific config key as a bool
func (config *Config) BoolValue(key string) (boolval bool) {
	str := config.StringValue(key)
	boolval, _ = strconv.ParseBool(str)
	return
}
