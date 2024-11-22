package api

import (
	"context"
	"fmt"
	"strings"
)

// BCrypt hashed secrets have a 72 character limit
const MaxSecretLength = 72

// WeakSecretError encodes an error that a secret does not meet strength
// requirements. It is handled specially in errors.go as it gets transformed to
// a HTTPError with a special weak_secret field that encodes the Reasons
// slice.
type WeakSecretError struct {
	Message string   `json:"message,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func (e *WeakSecretError) Error() string {
	return e.Message
}

func (a *API) checkSecretStrength(ctx context.Context, secret string) error {
	config := a.config

	if len(secret) > MaxSecretLength {
		return badRequestError(ErrorCodeValidationFailed, fmt.Sprintf("Secret cannot be longer than %v characters", MaxSecretLength))
	}

	var messages, reasons []string

	if len(secret) < config.Secret.MinLength {
		reasons = append(reasons, "length")
		messages = append(messages, fmt.Sprintf("Secret should be at least %d characters.", config.Secret.MinLength))
	}

	for _, characterSet := range config.Secret.RequiredCharacters {
		if characterSet != "" && !strings.ContainsAny(secret, characterSet) {
			reasons = append(reasons, "characters")

			messages = append(messages, fmt.Sprintf("Secret should contain at least one character of each: %s.", strings.Join(config.Secret.RequiredCharacters, ", ")))

			break
		}
	}

	if len(reasons) > 0 {
		return &WeakSecretError{
			Message: strings.Join(messages, " "),
			Reasons: reasons,
		}
	}

	return nil
}
