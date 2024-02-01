package util

import "encoding/base64"

// IsBase64 checks if a given string is a valid Base64 standard encoded string.
func IsBase64(str string) bool {
	_, err := base64.StdEncoding.DecodeString(str)
	return err == nil
}

// Base64Encode encodes a string using Base64 encoding.
func Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

// Base64Decode decodes a Base64 encoded string.
func Base64Decode(encodedStr string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// UrlSafeBase64Encode encodes a string using URL-safe Base64 encoding without padding.
func UrlSafeBase64Encode(str string) string {
	return base64.URLEncoding.EncodeToString([]byte(str))
}

// UrlSafeBase64Decode decodes a URL-safe Base64 encoded string.
func UrlSafeBase64Decode(encodedStr string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		bytes, err = base64.URLEncoding.DecodeString(encodedStr)
		if err != nil {
			return "", err
		}
	}
	return string(bytes), nil
}
