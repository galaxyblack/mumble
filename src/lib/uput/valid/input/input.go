package validinput

import (
	"errors"
	"reflect"
)

type InputData struct {
	Kind        reflect.Kind
	Data        interface{}
	Validations []Validation
}

//
// Input Validation
//==================================================================
func New(data interface{}) (input InputData) {
	input.Kind = reflect.TypeOf(data).Kind()
	if input.Kind != reflect.Invalid {
		input.Data = data
	}
	return input
}

//
// Input Data Helpers
//==================================================================
func (input InputData) IsValid() bool {
	return (len(input.InputErrors()) == 0)
}

//
// Validations
//==================================================================
func (input InputData) ValidationDescriptions() (descriptions []string) {
	for _, v := range input.Validations {
		descriptions = append(descriptions, v.String())
	}
	return descriptions
}

//
// InputErrors
//==================================================================
func (input InputData) InputErrors() (inputErrors []Validation) {
	for _, validation := range input.Validations {
		if !validation.IsValid {
			inputErrors = append(inputErrors, validation)
		}
	}
	return inputErrors
}
func (input InputData) Errors() (outputErrors []error) {
	for _, inputError := range input.InputErrors() {
		outputErrors = append(outputErrors, errors.New((inputError.Error())))
	}
	return outputErrors
}
func (input InputData) ErrorMessages() (errorMessages []string) {
	for _, inputError := range input.InputErrors() {
		errorMessages = append(errorMessages, inputError.Error())
	}
	return errorMessages
}
func (input InputData) ErrorCount() int {
	return len(input.InputErrors())
}

//
// Append Validations/Errors
//==================================================================
// TODO: Should Values be []interface{}?
func (input InputData) AppendValidation(validation Validation) InputData {
	if GlobalTextEnabled {
		text, exists := GlobalText[validation.Key]
		if exists {
			validation.Text = text
		}
	}
	validation.ValidateText()
	input.Validations = append(input.Validations, validation)
	return input
}

//
// Localize Validation Descriptions
//==================================================================
// Update Last Added Validation/Error Text
func (input InputData) SetLastValidationText(text ValidationText) InputData {
	if len(input.Validations) > 0 {
		lastText := input.Validations[len(input.Validations)-1].Text
		if IsTextValid(text.Error) {
			lastText.Error = text.Error
		}
		if IsTextValid(text.Description) {
			lastText.Description = text.Description
		}
		input.Validations[len(input.Validations)-1].Text = lastText
	}
	return input
}
func (input InputData) SetValidationText(key ValidationKey, newText ValidationText) InputData {
	text, index, exists := input.GetValidation(key)
	if exists {
		text = ValidationText{}
	}
	if !IsTextValid(newText.Description) {
		text.Description = newText.Description
	}
	if !IsTextValid(newText.Error) {
		text.Error = newText.Error
	}
	if IsValidationTextValidOrEmpty(text) {
		input.Validations[index].Text = text
		if GlobalTextEnabled {
			SetGlobalText(key, text)
		}
	}
	return input
}

// Helpers to simplify passing strings maps, which would be used by most people loading
// localization from YAML or JSON.
func (input InputData) SetErrorMessagesStrings(textMap map[ValidationKey]string) InputData {
	for key, text := range textMap {
		input.SetValidationText(key, ValidationText{Error: text})
	}
	return input
}
func (input InputData) SetValidationDescriptionsStrings(textMap map[ValidationKey]string) InputData {
	for key, text := range textMap {
		input.SetValidationText(key, ValidationText{Description: text})
	}
	return input
}
