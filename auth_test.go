package twitterclone

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterInput_Sanitize(t *testing.T) {
	input := RegisterInput{
		Username:        "beaver",
		Email:           "Test@example.com",
		Password:        "password",
		ConfirmPassword: "password",
	}

	expected := RegisterInput{
		Username:        "beaver",
		Email:           "test@example.com",
		Password:        "password",
		ConfirmPassword: "password",
	}
	input.Sanitize()

	require.Equal(t, expected, input)
}

func TestRegisterInput_Validate(t *testing.T) {
	testCases := []struct {
		name  string
		input RegisterInput
		err   error
	}{
		{
			name: "valid",
			input: RegisterInput{
				Username:        "beaver",
				Email:           "test@example.com",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: nil,
		},
		{
			name: "invalid email",
			input: RegisterInput{
				Username:        "beaver",
				Email:           "test",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "too short username",
			input: RegisterInput{
				Username:        "b",
				Email:           "test@example.com",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "too short password",
			input: RegisterInput{
				Username:        "beaver",
				Email:           "test@example.com",
				Password:        "pass",
				ConfirmPassword: "pass",
			},
			err: ErrValidation,
		},
		{
			name: "confirm password does not match password",
			input: RegisterInput{
				Username:        "beaver",
				Email:           "test@example.com",
				Password:        "password",
				ConfirmPassword: "password123",
			},
			err: ErrValidation,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
