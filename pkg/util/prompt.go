package util

import (
	"fmt"
	"strings"

	"github.com/jschauma/getpass"
)

func PromptPassword(prompt string) (string, error) {
	if !strings.HasSuffix(prompt, ": ") {
		prompt += ": "
	}
	fmt.Print(prompt)
	p, err := getpass.Getpass()
	if err != nil {
		return "", err
	}
	return p, nil
}
