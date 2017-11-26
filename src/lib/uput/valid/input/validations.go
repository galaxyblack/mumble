package validinput

import (
	"reflect"
	"strings"
	"unicode"
)

type ValidationKey int
type ValidationText struct {
	Error       string
	Description string
}

// TODO: Determine if []interface{} would be more fluid for Values field
type Validation struct {
	Kind        reflect.Kind
	Key         ValidationKey
	Values      []string
	Text        ValidationText
	DefaultText ValidationText
	IsValid     bool
}

func (v Validation) ValidateText() {
	if !IsTextValid(v.Text.Description) {
		if v.DefaultText.Description != "" {
			v.Text.Description = v.DefaultText.Description
		} else if v.Text.Description != "" {
			v.Text.Description = ""
		}
	}
	if !IsTextValid(v.Text.Error) {
		if v.DefaultText.Error != "" {
			v.Text.Error = v.DefaultText.Error
		} else if v.Text.Error != "" {
			v.Text.Error = ""
		}
	}
}

//
// Global Loaded Localized Validation Text
//==================================================================
var GlobalTextEnabled bool
var GlobalText map[ValidationKey]ValidationText

func InitializeGlobalText() {
	if GlobalText == nil {
		GlobalText = make(map[ValidationKey]ValidationText)
	}
}
func SetGlobalText(key ValidationKey, text ValidationText) {
	if IsValidationTextValidOrEmpty(text) {
		GlobalText[key] = text
	}
}

// Load From map[ValidationKey]ValidationText form used in DefaultText maps
func LoadGlobalText(textMap map[ValidationKey]ValidationText) (loadCount int) {
	if GlobalTextEnabled {
		InitializeGlobalText()
		for key, text := range textMap {
			globalText, exists := GlobalText[key]
			if !exists {
				globalText = ValidationText{}
			}
			if IsTextValid(text.Description) {
				globalText.Description = text.Description
			}
			if IsTextValid(text.Error) {
				globalText.Error = text.Error
			}
			if IsValidationTextValidOrEmpty(globalText) {
				GlobalText[key] = globalText
				loadCount++
			}
		}
	}
	return loadCount
}

//
// Individual InputData Validation Management
//==================================================================
func (input InputData) GetValidation(key ValidationKey) (ValidationText, int, bool) {
	for index, validation := range input.Validations {
		if validation.Key == key {
			return validation.Text, index, true
		}
	}
	return ValidationText{}, 0, false
}

//
// Validation/Error Text (string) Validations
//==================================================================
func IsTextValid(text string) bool {
	// valid.IfValidationText.Content.IsBetween(2, 64)
	if !(2 <= len(text) && len(text) <= 64) {
		return false
	} else {
		// valid.IfValidationText.Content.IsPrintable
		// TODO: Should be iterating over runes? Think this may not be assuming UTF8 runes
		for _, r := range text {
			if !unicode.IsPrint(r) {
				return false
			}
		}
	}
	return true
}
func IsTextValidOrEmpty(text string) bool {
	return (IsTextValid(text) || len(text) == 0)
}
func IsValidationTextValid(text ValidationText) bool {
	return (IsTextValid(text.Description) && IsTextValid(text.Error))
}
func IsValidationTextValidOrEmpty(text ValidationText) bool {
	return (IsTextValidOrEmpty(text.Description) && IsTextValidOrEmpty(text.Error))
}

//
// Compile Output Message
//==================================================================
func (v Validation) output(text string) string {
	switch len(v.Values) {
	case 0:
		return v.Kind.String() + ": " + text
	case 1:
		return v.Kind.String() + ": " + text + ": " + v.Values[0]
	case 2:
		return v.Kind.String() + ": " + text + ": " + v.Values[0] + " - " + v.Values[1]
	default:
		return v.Kind.String() + ": " + text + ": [ " + strings.Join(v.Values, ", ") + " ]"
	}
}

//
// Output Strings for Validation and Error
//==================================================================
func (v Validation) Error() string {
	return v.output(v.Text.Error)
}
func (v Validation) String() string {
	return v.output(v.Text.Description)
}
