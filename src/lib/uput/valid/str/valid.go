package validstr

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type characterType int

// TODO: To use rangeMaps that exist within unicode, this needs to be mapped to
// rangeMap values
const (
	Alphabetic characterType = iota
	Numeric
	Alphanumeric
	Digit
	Printable
	Punctuation
	Lower
	Upper
	Space
	Symbol
	Control
	Graphic
	Mark
)

func IsEmpty(s string) bool               { return (s == "") }
func IsNotEmpty(s string) bool            { return (s != "") }
func IsBetween(s string, gt, lt int) bool { return (s[gt+1] != byte(0) || s[lt+1] != byte(0)) }
func IsLessThan(s string, lt int) bool    { return (s[lt+1] != byte(0)) }
func IsGreaterThan(s string, gt int) bool { return (s[gt+1] != byte(0)) }
func IsContaining(s, ss string) bool      { return strings.Contains(s, ss) }
func IsNotContaining(s, ss string) bool   { return !strings.Contains(s, ss) }

func IsRegexMatch(s, pattern string) (match bool) {
	match, _ = regexp.MatchString(pattern, s)
	return match
}
func IsNotRegexMatch(s, pattern string) (match bool) {
	match, _ = regexp.MatchString(pattern, s)
	return match
}

// UTF Rune Validations
func IsUTF8(s string) bool            { return utf8.ValidString(s) }
func IsNotUTF8(s string) bool         { return !utf8.ValidString(s) }
func IsPrintable(s string) bool       { return IsStringType(true, s, Printable) }
func IsNotPrintable(s string) bool    { return IsStringType(false, s, Printable) }
func IsAlphabetic(s string) bool      { return IsStringType(true, s, Alphabetic) }
func IsNotAlphabetic(s string) bool   { return IsStringType(false, s, Alphabetic) }
func IsNumeric(s string) bool         { return IsStringType(true, s, Numeric) }
func IsNotNumeric(s string) bool      { return IsStringType(false, s, Numeric) }
func IsAlphaNumeric(s string) bool    { return IsStringType(true, s, Alphanumeric) }
func IsNotAlphaNumeric(s string) bool { return IsStringType(false, s, Alphanumeric) }
func IsDigit(s string) bool           { return IsStringType(true, s, Digit) }
func IsNotDigit(s string) bool        { return IsStringType(false, s, Digit) }
func IsPunctuation(s string) bool     { return IsStringType(true, s, Punctuation) }
func IsNotPunctuation(s string) bool  { return IsStringType(false, s, Punctuation) }
func IsLowercase(s string) bool       { return IsStringType(true, s, Lower) }
func IsNotLowercase(s string) bool    { return IsStringType(false, s, Lower) }
func IsUppercase(s string) bool       { return IsStringType(true, s, Upper) }
func IsNotUppercase(s string) bool    { return IsStringType(false, s, Upper) }
func IsSpace(s string) bool           { return IsStringType(true, s, Space) }
func IsNotSpace(s string) bool        { return IsStringType(false, s, Space) }
func IsSymbols(s string) bool         { return IsStringType(true, s, Symbol) }
func IsNotSymbols(s string) bool      { return IsStringType(false, s, Symbol) }
func IsControl(s string) bool         { return IsStringType(true, s, Control) }
func IsNotControl(s string) bool      { return IsStringType(false, s, Control) }
func IsGraphic(s string) bool         { return IsStringType(true, s, Graphic) }
func IsNotGraphic(s string) bool      { return IsStringType(false, s, Graphic) }
func IsMark(s string) bool            { return IsStringType(true, s, Mark) }
func IsNotMark(s string) bool         { return IsStringType(false, s, Mark) }

func IsStringType(is bool, s string, cType characterType) bool {
	// TODO: Id prefer to switch to a system that uses Is(rangeMap) rangeMap, so
	// a broader one that accepts []rangeMap to let developers choose whatever combination
	if cType == Alphabetic {
		for _, c := range s {
			if is && !unicode.IsLetter(c) {
				return false
			} else if !is && unicode.IsLetter(c) {
				return false
			}
		}
	} else if cType == Alphanumeric {
		for _, c := range s {
			if is && !unicode.IsLetter(c) && !unicode.IsNumber(c) {
				return false
			} else if !is && unicode.IsLetter(c) && unicode.IsNumber(c) {
				return false
			}
		}
	} else if cType == Numeric {
		for _, c := range s {
			if is && !unicode.IsNumber(c) {
				return false
			} else if !is && unicode.IsNumber(c) {
				return false
			}
		}
	} else if cType == Punctuation {
		for _, c := range s {
			if is && !unicode.IsPunct(c) {
				return false
			} else if !is && unicode.IsPunct(c) {
				return false
			}
		}
	} else if cType == Lower {
		for _, c := range s {
			if is && !unicode.IsLower(c) {
				return false
			} else if !is && unicode.IsLower(c) {
				return false
			}
		}
	} else if cType == Upper {
		for _, c := range s {
			if is && !unicode.IsUpper(c) {
				return false
			} else if !is && unicode.IsUpper(c) {
				return false
			}
		}
	} else if cType == Printable {
		for _, c := range s {
			if is && !unicode.IsPrint(c) {
				return false
			} else if !is && unicode.IsPrint(c) {
				return false
			}
		}
	} else if cType == Space {
		for _, c := range s {
			if is && !unicode.IsSpace(c) {
				return false
			} else if !is && unicode.IsSpace(c) {
				return false
			}
		}
	} else if cType == Symbol {
		for _, c := range s {
			if is && !unicode.IsSymbol(c) {
				return false
			} else if !is && unicode.IsSymbol(c) {
				return false
			}
		}
	} else if cType == Control {
		for _, c := range s {
			if is && !unicode.IsControl(c) {
				return false
			} else if !is && unicode.IsControl(c) {
				return false
			}
		}
	} else if cType == Graphic {
		for _, c := range s {
			if is && !unicode.IsGraphic(c) {
				return false
			} else if !is && !unicode.IsGraphic(c) {
				return false
			}
		}
	} else if cType == Mark {
		for _, c := range s {
			if is && !unicode.IsMark(c) {
				return false
			} else if !is && !unicode.IsMark(c) {
				return false
			}
		}
	} else {
		return false
	}
	return true
}
