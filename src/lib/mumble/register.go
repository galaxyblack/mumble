package mumble

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"io/ioutil"
	"net/http"
)

type Register struct {
	XMLName  xml.Name `xml:"server"`
	Version  string   `xml:"version"`
	Release  string   `xml:"release"`
	Name     string   `xml:"name"`
	Host     string   `xml:"host"`
	Password string   `xml:"password"`
	Port     int      `xml:"port"`
	URL      string   `xml:"url"`
	Digest   string   `xml:"digest"`
	Users    int      `xml:"users"`
	Channels int      `xml:"channels"`
	Location string   `xml:"location"`
}

// TODO: This should be changed, not hardcoded (read from config)
const registerURL = "https://mumble.hive.no/register.cgi"

// Determines whether a server is public by checking whether the
// config values required for public registration are set.
//
// This function is used to determine whether or not to periodically
// contact the master server list and update this server's metadata.
func (server *Server) IsPublic() bool {
	// TODO: Just return the if statement instead of checking then creating a false to pass through
	// TODO: don't count entire strings if you just need to check the value of a single index
	if len(server.config.StringValue("RegisterName")) == 0 {
		return false
	}
	if len(server.config.StringValue("RegisterHost")) == 0 {
		return false
	}
	if len(server.config.StringValue("RegisterPassword")) == 0 {
		return false
	}
	if len(server.config.StringValue("RegisterWebUrl")) == 0 {
		return false
	}
	return true
}

// Perform a public server registration update.
//
// When a Mumble server connects to the master server
// for registration, it connects using its server certificate
// as a client certificate for authentication purposes.
func (server *Server) RegisterPublicServer() {
	if !server.IsPublic() {
		return
	}

	// Fetch the server's certificates and put them in a tls.Config.
	// We need the certificate chain to be able to use it in our client
	// certificate chain to the registration server, and we also need to
	// include a digest of the leaf certiifcate in the registration XML document
	// we send off to the server.
	config := &tls.Config{}
	for _, certificate := range server.tlsConfig.Certificates {
		config.Certificates = append(config.Certificates, certificate)
	}

	// TODO: Don't hash with sha1, its not secure, and the same lib has better options
	hasher := sha1.New()
	hasher.Write(config.Certificates[0].Certificate[0])
	digest := hex.EncodeToString(hasher.Sum(nil))

	// Render registration XML template
	registrationData := Register{
		Name:     server.config.StringValue("RegisterName"),
		Host:     server.config.StringValue("RegisterHost"),
		Password: server.config.StringValue("RegisterPassword"),
		URL:      server.config.StringValue("RegisterWebURL"),
		Location: server.config.StringValue("RegisterLocation"),
		Port:     server.CurrentPort(),
		Digest:   digest,
		Users:    len(server.clients),
		Channels: len(server.Channels),
		// TODO: We have this loaded into a version file and hardcoded, so... lets use it
		Version: "0.1.0",
		// TODO: Pull this from a build config file
		Release: "Mumble Git",
	}
	buffer := bytes.NewBuffer(nil)
	err := xml.NewEncoder(buffer).Encode(registrationData)
	if err != nil {
		// TODO: Centralized logging!!!!!!!!!
		//server.Printf("register: unable to marshal xml: %v", err)
		return
	}

	// Post registration XML data to server asynchronously in its own goroutine
	go func() {
		transport := &http.Transport{
			TLSClientConfig: config,
		}
		client := &http.Client{Transport: transport}
		result, err := client.Post(registerURL, "text/xml", ioutil.NopCloser(buffer))
		if err != nil {
			// TODO: Centralized logging!!!!!!!!!
			//server.Printf("register: unable to post registration request: %v", err)
			return
		}
		//bodyBytes, err := ioutil.ReadAll(result.Body)
		if err == nil {
			// TODO Not using registerMessage till db is added
			//registerMessage := string(bodyBytes)
			if result.StatusCode == 200 {
				// TODO: Centralized logging!!!!!!!!!
				//server.Printf("register: %v", registerMessage)
			} else {
				// TODO: Centralized logging!!!!!!!!!
				//server.Printf("register: (status %v) %v", result.StatusCode, registerMessage)
			}
		} else {
			// TODO: Centralized logging!!!!!!!!!
			//server.Printf("register: unable to read post response: %v", err)
			return
		}
	}()
}
