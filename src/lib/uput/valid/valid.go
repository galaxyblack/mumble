package valid

import (
	//"strings"
	"errors"
	"lib/uput/valid/str"
)

// something i wrote not really relevant but may be usful, delete when not
//type Validate interface {
//	InputData()
//	ValidationSchema() map[string]string
//}

// How does this work? should be chaining
type ValidateStringFunction func(input string) (output string, errors []error)

type ValidateString interface {
	NotEmpty() InputData
	Regex(regex string) InputData
	Validation(f ValidateStringFunction) InputData
}

//func (v InputData) Validate(function ValidateStringFunction) InputData {
// should be executing the function
//v.function = function
//	return v
//}

type dataType int

const (
	StringType dataType = iota
	IntType
)

// Using a generic struct for input data enables us to simplify the codebase
type InputData struct {
	dataType // here we can use this to make the funcs more generic
	// 1 = int
	// 0 = string
	stringData string
	intData    int
	uintData   uint

	errors        []error
	errorMessages map[string]string
	validations   map[string]ValidateStringFunction
}

//
// Input function
//
func IfString(input string) InputData {
	return InputData{
		dataType:   StringType,
		stringData: input,
	}
}

//
// Output function - maybe a function with the ability specify messages
//
func (input InputData) IsValid() (interface{}, []error) {
	if input.dataType == StringType {
		return input.stringData, input.errors
	} else {
		input.errors = append(input.errors, errors.New("unknown data type"))
		return nil, input.errors
	}
}

// create a generic output that returns string and errors
// this function should also take in errors for inline modding of errors

//
// Transforms - could be replaced with a single transformation call
//
func (input InputData) Transform() InputData {
	// pass in transforms
	return input
}

//
// String Validations - each function should accept error message text?
//
func (input InputData) IsEmpty() InputData {
	if validstr.IsEmpty(input.stringData) {
		input.errors = append(input.errors, errors.New("look up error message"))
	}
	return input
}

func (input InputData) IsNotEmpty() InputData {
	if input.stringData == "" {
		input.errors = append(input.errors, errors.New("look up error message"))
	}
	return input
}

func (input InputData) Regex(regex string) InputData {
	//input.regex = regex
	return input
}
