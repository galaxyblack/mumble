package validstr

import (
	"strconv"

	validinput "lib/uput/valid/input"
	validate "lib/uput/valid/str/is"
)

type StringInput struct {
	data  string
	input validinput.InputData
}

//
// Validation Input Function
// ==========================================================================
func If(s string) StringInput {
	if validinput.GlobalTextEnabled {
		if validinput.GlobalText == nil {
			validinput.LoadGlobalText((DefaultStringValidationText()))
		}
	}
	return StringInput{
		data:  s,
		input: validinput.New(s),
	}
}

//
// Validation Output Function
// ==========================================================================
func (s StringInput) IsValid() (bool, string, []error) {
	//onlyErrors := false
	//statusJSON, err := inputstatus.GetStatus(s.input, onlyErrors).Encode(
	//	map[inputstatus.EncodeOption]string{
	//		inputstatus.Format: "json",
	//		inputstatus.Indent: "  ",
	//	},
	//)
	//if err == nil {
	//	fmt.Println(statusJSON)
	//}
	return s.input.IsValid(), s.data, s.input.Errors()
}

//
// Custom Validations
// ==========================================================================

// TODO: Add niche validations from /is/ like /is/email

//
// Default Error Message & Validation Descriptions
// ==========================================================================
// TODO: Should bring back the KeyToString function so its easier to work with for devs
func DefaultErrorMessages() (messages map[validinput.ValidationKey]string) {
	for key, text := range DefaultStringValidationText() {
		messages[key] = text.Error
	}
	return messages
}
func DefaultValidationDescriptions() (descriptions map[validinput.ValidationKey]string) {
	for key, text := range DefaultStringValidationText() {
		descriptions[key] = text.Description
	}
	return descriptions
}

// Localize Error Message & Validation Descriptions
// ==========================================================================
func (s StringInput) ErrorMessage(message string) StringInput {
	s.input = s.input.SetLastValidationText(validinput.ValidationText{Error: message})
	return s
}
func (s StringInput) ValidationDescription(message string) StringInput {
	s.input = s.input.SetLastValidationText(validinput.ValidationText{Description: message})
	return s
}
func (s StringInput) ValidationText(description, message string) StringInput {
	s.input = s.input.SetLastValidationText(validinput.ValidationText{Description: message})
	return s
}
func (s StringInput) SetValidationText(key, message, description string) StringInput {
	s.input = s.input.SetValidationText((StringToValidationKey(key)), validinput.ValidationText{Description: description, Error: message})
	return s
}
func (s StringInput) ErrorMessages(errorMessages map[string]string) StringInput {
	for key, message := range errorMessages {
		s.input = s.input.SetValidationText((StringToValidationKey(key)), validinput.ValidationText{Error: message})
	}
	return s
}
func (s StringInput) ValidationDescriptions(descriptions map[string]string) StringInput {
	for key, description := range descriptions {
		s.input = s.input.SetValidationText((StringToValidationKey(key)), validinput.ValidationText{Description: description})
	}
	return s
}

//
// Chainable String Validations
// ==========================================================================

func (s StringInput) Validate(key validinput.ValidationKey, values []string, valid bool) validinput.Validation {
	return validinput.Validation{
		Key:         key,
		Values:      values,
		Kind:        s.input.Kind,
		DefaultText: (GetDefeaultStringValidationText(key)),
		IsValid:     valid,
	}
}

//
// String Slice Validations
func (s StringInput) IsIn(list []string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(In, list, validate.IsInSlice(s.data, list)))
	return s
}
func (s StringInput) NotIn(list []string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(NotIn, list, !validate.IsInSlice(s.data, list)))
	return s
}

//
// String Length Validations
func (s StringInput) Required() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Required, nil, validate.IsNotEmpty(s.data)))
	//Required, nil, validate.IsNotEmpty(s.data))
	return s
}
func (s StringInput) IsEmpty() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Empty, nil, validate.IsEmpty(s.data)))
	return s
}
func (s StringInput) NotEmpty() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NotEmpty, nil, validate.IsEmpty(s.data)))
	return s
}
func (s StringInput) IsBlank() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Blank, nil, validate.IsBlank(s.data)))
	return s
}
func (s StringInput) IsNotBlank() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NotBlank, nil, validate.IsNotBlank(s.data)))
	return s
}
func (s StringInput) IsBetween(start, end int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(Between, []string{strconv.Itoa(start), strconv.Itoa(end)}, validate.IsBetween(s.data, start, end)))
	return s
}
func (s StringInput) IsLessThan(lt int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(LessThan, []string{strconv.Itoa(lt)}, validate.IsLessThan(s.data, lt)))
	return s
}
func (s StringInput) IsGreaterThan(gt int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(GreaterThan, []string{strconv.Itoa(gt)}, validate.IsGreaterThan(s.data, gt)))
	return s
}

//
// Substring Validation
// WARNING: DOES NOT WORK FOR UTF8 MATCHING
// This will let through look-alikes, like K
// and K for kelvin temperature.
func (s StringInput) Contains(ss string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(Contains, []string{ss}, validate.Contains(s.data, ss)))
	return s
}
func (s StringInput) NotContaining(ss string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(NotContaining, []string{ss}, !validate.Contains(s.data, ss)))
	return s
}

//
// Regex Validation
func (s StringInput) IsRegexMatch(pattern string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(RegexMatch, []string{pattern}, validate.IsRegexMatch(s.data, pattern)))
	return s
}
func (s StringInput) NoRegexMatch(pattern string) StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoRegexMatch, []string{pattern}, !validate.IsRegexMatch(s.data, pattern)))
	return s
}

//
// UTF8 Validation
func (s StringInput) IsUTF8() StringInput {
	s.input = s.input.AppendValidation(s.Validate(UTF8, nil, validate.IsUTF8(s.data)))
	return s
}
func (s StringInput) NoUTF8() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoUTF8, nil, !validate.IsUTF8(s.data)))
	return s
}

//
// UTF8 Rune Validation
func (s StringInput) IsAlphabetic() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Alphabetic, nil, validate.Alphabetic(s.data, true, 0)))
	return s
}
func (s StringInput) NoAlphabetic() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoAlphabetic, nil, validate.Alphabetic(s.data, false, 0)))
	return s
}
func (s StringInput) MinAlphabeticCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinAlphabetic, nil, validate.Alphabetic(s.data, true, count)))
	return s
}
func (s StringInput) IsAlphanumeric() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Alphanumeric, nil, validate.Alphanumeric(s.data, true, 0)))
	return s
}
func (s StringInput) NoAlphanumeric() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoAlphanumeric, nil, validate.Alphanumeric(s.data, false, 0)))
	return s
}
func (s StringInput) IsNumeric() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Numeric, nil, validate.Numeric(s.data, true, 0)))
	return s
}
func (s StringInput) NoNumeric() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoNumeric, nil, validate.Numeric(s.data, false, 0)))
	return s
}
func (s StringInput) MinNumericCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinNumeric, nil, validate.Numeric(s.data, true, count)))
	return s
}
func (s StringInput) IsUppercase() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Uppercase, nil, validate.Uppercase(s.data, true, 0)))
	return s
}
func (s StringInput) NoUppercase() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoUppercase, nil, validate.Uppercase(s.data, false, 0)))
	return s
}
func (s StringInput) MinUppercaseCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinUppercase, nil, validate.Uppercase(s.data, true, count)))
	return s
}
func (s StringInput) IsLowercase() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Lowercase, nil, validate.Lowercase(s.data, true, 0)))
	return s
}
func (s StringInput) NoLowercase() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoLowercase, nil, validate.Lowercase(s.data, false, 0)))
	return s
}
func (s StringInput) MinLowercaseCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinLowercase, nil, validate.Lowercase(s.data, true, count)))
	return s
}
func (s StringInput) IsPrintable() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Printable, nil, validate.Printable(s.data, true, 0)))
	return s
}
func (s StringInput) NoPrintable() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoPrintable, nil, validate.Printable(s.data, false, 0)))
	return s
}
func (s StringInput) IsPunctuation() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Punctuation, nil, validate.Punctuation(s.data, true, 0)))
	return s
}
func (s StringInput) NoPunctuation() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoPunctuation, nil, validate.Punctuation(s.data, false, 0)))
	return s
}
func (s StringInput) MinPunctuationCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinPunctuation, nil, validate.Punctuation(s.data, true, count)))
	return s
}
func (s StringInput) IsSymbols() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Symbols, nil, validate.Symbols(s.data, true, 0)))
	return s
}
func (s StringInput) NoSymbols() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoSymbols, nil, validate.Symbols(s.data, false, 0)))
	return s
}
func (s StringInput) MinSymbolCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinSymbols, nil, validate.Symbols(s.data, true, count)))
	return s
}
func (s StringInput) IsWhitespaces() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Spaces, nil, validate.Whitespaces(s.data, true, 0)))
	return s
}
func (s StringInput) NoWhitespaces() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoSpaces, nil, validate.Whitespaces(s.data, false, 0)))
	return s
}
func (s StringInput) IsControlCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Controls, nil, validate.ControlCharacters(s.data, true, 0)))
	return s
}
func (s StringInput) NoControlCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoControls, nil, validate.ControlCharacters(s.data, false, 0)))
	return s
}
func (s StringInput) IsGraphicCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Graphics, nil, validate.GraphicCharacters(s.data, true, 0)))
	return s
}
func (s StringInput) NoGraphicCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoGraphics, nil, validate.GraphicCharacters(s.data, false, 0)))
	return s
}
func (s StringInput) IsMarkCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Marks, nil, validate.MarkCharacters(s.data, true, 0)))
	return s
}
func (s StringInput) NoMarkCharacters() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoMarks, nil, validate.MarkCharacters(s.data, false, 0)))
	return s
}
func (s StringInput) IsDigits() StringInput {
	s.input = s.input.AppendValidation(s.Validate(Digits, nil, validate.Digits(s.data, true, 0)))
	return s
}
func (s StringInput) NoDigits() StringInput {
	s.input = s.input.AppendValidation(s.Validate(NoDigits, nil, validate.Digits(s.data, false, 0)))
	return s
}
func (s StringInput) MinDigitCount(count int) StringInput {
	s.input = s.input.AppendValidation(s.Validate(MinDigits, nil, validate.Digits(s.data, true, count)))
	return s
}
