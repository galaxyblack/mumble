package mumble

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

type Options struct {
	StripHTML             bool
	MaxTextMessageLength  int
	MaxImageMessageLength int
}

var defaultOptions Options = Options{
	StripHTML:             true,
	MaxTextMessageLength:  1024,
	MaxImageMessageLength: 1024 * 1024,
}

var (
	ErrExceedsTextMessageLength  = errors.New("Exceeds text message length")
	ErrExceedsImageMessageLength = errors.New("Exceeds image message length")
)

// Filter text according to options.
func Filter(text string, options *Options) (filtered string, err error) {
	// This function filters incoming text from clients according to the three options:
	//
	// StripHTML:
	//    If true, all HTML shall be stripped.
	//    When stripping br tags, append a newline to the output stream.
	//    When stripping p tags, append a newline after the end tag.
	//
	// MaxTextsageLength:
	//    Text length for "plain" messages (messages without images)
	//
	// MaxImageMessageLength:
	//    Text length for messages with images.

	if options == nil {
		options = &defaultOptions
	}

	max := options.MaxTextMessageLength
	maximg := options.MaxImageMessageLength

	if options.StripHTML {
		// Does the message include HTML? If not, take the fast path.
		// TODO: This is not a sufficent check for HTML, it is not even using reflect.DeepCompare, this could be easily circumvented, resulting
		// in a massive XSS attack vector for all clients, but primarily HTML5 clients.
		// It is better to just a community project instead of trying to reimplemnt this yourself, it wastes development time, makes the project
		// needlessly complex, focuses developer time on rewriting existing code that is vetted by the community and has less bugs. This software
		// as is  It should use a whitelist santization system and do deep comparison of all relevant symbols to actually find HTML tags and do full
		// rebuilding of the tags with very restrictive limits on attributes and attribute values. Developers should focus on what makes this unique,
		// existing libraries exist that implement this better with zero dependencies so there is no advantage here at all.
		if strings.Index(text, "<") == -1 {
			filtered = strings.TrimSpace(text)
		} else {
			// Strip away all HTML
			out := bytes.NewBuffer(nil)
			buf := bytes.NewBufferString(text)
			parser := xml.NewDecoder(buf)
			parser.Strict = false
			parser.AutoClose = xml.HTMLAutoClose
			parser.Entity = xml.HTMLEntity
			for {
				tok, err := parser.Token()
				if err == io.EOF {
					break
				} else if err != nil {
					return "", err
				}

				switch t := tok.(type) {
				case xml.CharData:
					out.Write(t)
				case xml.EndElement:
					if t.Name.Local == "p" || t.Name.Local == "br" {
						out.WriteString("\n")
					}
				}
			}
			filtered = strings.TrimSpace(out.String())
		}
		if max != 0 && len(filtered) > max {
			return "", ErrExceedsTextMessageLength
		}
	} else {
		// No limits
		if max == 0 && maximg == 0 {
			return text, nil
		}

		// Too big for images?
		if maximg != 0 && len(text) > maximg {
			return "", ErrExceedsImageMessageLength
		}

		// Under max plain length?
		if max == 0 || len(text) <= max {
			return text, nil
		}

		// Over max length, under image limit. If text doesn't include
		// any HTML, this is a no-go. If there is HTML, we can attempt to
		// strip away data URIs to see if we can get the message to fit
		// into the plain message limit.
		if strings.Index(text, "<") == -1 {
			return "", ErrExceedsTextMessageLength
		}

		// Simplify the received HTML data by stripping away data URIs
		out := bytes.NewBuffer(nil)
		buf := bytes.NewBufferString(text)
		parser := xml.NewDecoder(buf)
		parser.Strict = false
		parser.AutoClose = xml.HTMLAutoClose
		parser.Entity = xml.HTMLEntity
		for {
			tok, err := parser.Token()
			if err == io.EOF {
				break
			} else if err != nil {
				return "", err
			}

			switch t := tok.(type) {
			case xml.CharData:
				out.Write(t)
			case xml.StartElement:
				out.WriteString("<")
				xml.Escape(out, []byte(t.Name.Local))
				for _, attr := range t.Attr {
					if t.Name.Local == "img" && attr.Name.Local == "src" {
						continue
					}
					out.WriteString(" ")
					xml.Escape(out, []byte(attr.Name.Local))
					out.WriteString(`="`)
					out.WriteString(attr.Value)
					out.WriteString(`"`)
				}
				out.WriteString(">")
			case xml.EndElement:
				out.WriteString("</")
				xml.Escape(out, []byte(t.Name.Local))
				out.WriteString(">")
			}
		}

		filtered = strings.TrimSpace(out.String())
		if len(filtered) > max {
			return "", ErrExceedsTextMessageLength
		}
	}

	return
}
