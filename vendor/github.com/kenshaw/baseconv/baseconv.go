// Package baseconv converts a string in an arbitrary base to any other
// arbitrary base.
package baseconv

import (
	"fmt"
	"unicode/utf8"
)

// Error is a base conversion error.
type Error string

// Error satisfies the error interface.
func (err Error) Error() string {
	return string(err)
}

// InvalidCharacterError is an invalid character error.
type InvalidCharacterError struct {
	r      rune
	pos, n int
}

// Error satisfies the error interface.
func (err *InvalidCharacterError) Error() string {
	return fmt.Sprintf("invalid character '%c' at position %d (%d)", err.r, err.pos, err.n)
}

// Error values.
const (
	// ErrInvalidNumber is the invalid number error.
	ErrInvalidNumber Error = "invalid number"

	// ErrInvalidFromBase is the invalid from base error.
	ErrInvalidFromBase Error = "invalid fromBase"

	// ErrInvalidToBase is the invalid to base error.
	ErrInvalidToBase Error = "invalid toBase"
)

// Convert num from specified base to a different base.
func Convert(num, fromBase, toBase string) (string, error) {
	if num == "" {
		return "", ErrInvalidNumber
	}
	if len(fromBase) < 2 {
		return "", ErrInvalidFromBase
	}
	if len(toBase) < 2 {
		return "", ErrInvalidToBase
	}
	// rune counts
	fromLenRunes := utf8.RuneCountInString(fromBase)
	toLenRunes := utf8.RuneCountInString(toBase)
	numLen := utf8.RuneCountInString(num)
	// loop over unicode runes in original string and store representative
	// values in number -- number[i] = index(num[i], fromBase)
	number, ipos := make([]int, numLen), 0
	for i, r := range num {
		jpos, found := 0, false
		for _, s := range fromBase {
			if r == s {
				number[ipos] = jpos
				found = true
				break
			}
			jpos++
		}
		// if character wasn't found in fromBase, then error
		if !found {
			return "", &InvalidCharacterError{r, ipos, i}
		}
		ipos++
	}
	// split the runes in toBase
	todigits, idx := make([]rune, toLenRunes), 0
	for _, r := range toBase {
		todigits[idx] = r
		idx++
	}
	// loop until whole number is converted
	var result []rune
	for {
		divide, newlen := 0, 0
		// perform division manually (which is why this works with big numbers)
		for i := 0; i < numLen; i++ {
			divide = divide*fromLenRunes + number[i]
			if divide >= toLenRunes {
				number[newlen] = divide / toLenRunes
				divide = divide % toLenRunes
				newlen++
			} else if newlen > 0 {
				number[newlen] = 0
				newlen++
			}
		}
		numLen, result = newlen, append(result, todigits[divide])
		if newlen == 0 {
			break
		}
	}
	// reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result), nil
}

const (
	// DigitsBin represents binary digits
	DigitsBin = "01"

	// DigitsOct represents octal Digits
	DigitsOct = "01234567"

	// DigitsDec represents decimal digits
	DigitsDec = "0123456789"

	// DigitsHex represents hex digits
	DigitsHex = "0123456789abcdef"

	// Digits36 represents base36 digits
	Digits36 = "0123456789abcdefghijklmnopqrstuvwxyz"

	// Digits62 represents base62 digits
	Digits62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// Digits64 represents base64 digits
	Digits64 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
)

// EncodeBinFromDec encodes a string to DigitsBin from DigitsDec.
func EncodeBinFromDec(num string) (string, error) {
	return Convert(num, DigitsDec, DigitsBin)
}

// DecodeBinToDec decodes a string from DigitsBin to DigitsDec.
func DecodeBinToDec(num string) (string, error) {
	return Convert(num, DigitsBin, DigitsDec)
}

// EncodeOctFromDec encodes a string to DigitsOct from DigitsDec.
func EncodeOctFromDec(num string) (string, error) {
	return Convert(num, DigitsDec, DigitsOct)
}

// DecodeOctToDec decodes a string from DigitsOct to DigitsDec.
func DecodeOctToDec(num string) (string, error) {
	return Convert(num, DigitsOct, DigitsDec)
}

// EncodeHexFromDec encodes a string to DigitsHex from DigitsDec.
func EncodeHexFromDec(num string) (string, error) {
	return Convert(num, DigitsDec, DigitsHex)
}

// DecodeHexToDec decodes a string from DigitsHex to DigitsDec.
func DecodeHexToDec(num string) (string, error) {
	return Convert(num, DigitsHex, DigitsDec)
}

// Encode36FromDec encodes a string to Digits36 from DigitsDec.
func Encode36FromDec(num string) (string, error) {
	return Convert(num, DigitsDec, Digits36)
}

// Decode36ToDec decodes a string from Digits36 to DigitsDec.
func Decode36ToDec(num string) (string, error) {
	return Convert(num, Digits36, DigitsDec)
}

// Encode62FromDec encodes a string to Digits62 to DigitsDec.
func Encode62FromDec(num string) (string, error) {
	return Convert(num, DigitsDec, Digits62)
}

// Decode62ToDec decodes a string from Digits62 to DigitsDec.
func Decode62ToDec(num string) (string, error) {
	return Convert(num, Digits62, DigitsDec)
}

// Encode64FromDec encodes a string to Digits64 to DigitsDec.
func Encode64FromDec(num string) (string, error) {
	return Convert(num, DigitsDec, Digits64)
}

// Decode64ToDec decodes a string from Digits64 to DigitsDec.
func Decode64ToDec(num string) (string, error) {
	return Convert(num, Digits64, DigitsDec)
}
