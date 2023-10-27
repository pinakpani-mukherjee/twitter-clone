package domain

import (
	"context"
	"errors"
	"fmt"

	twitterclone "github.com/pinakpani-mukherjee/twitter-clone"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	UserRepo twitterclone.UserRepo
}

func NewAuthService(ur twitterclone.UserRepo) *AuthService {
	return &AuthService{
		UserRepo: ur,
	}
}

func (as *AuthService) Register(ctx context.Context, input twitterclone.RegisterInput) (twitterclone.AuthResponse, error) {
	input.Sanitize()
	if err := input.Validate(); err != nil {
		return twitterclone.AuthResponse{}, err
	}

	//Check if username is already taken
	if _, err := as.UserRepo.GetByUsername(ctx, input.Username); !errors.Is(err, twitterclone.ErrNotFound) {
		return twitterclone.AuthResponse{}, twitterclone.ErrUsernameTaken
	}
	//Check if email is already taken
	if _, err := as.UserRepo.GetByEmail(ctx, input.Email); !errors.Is(err, twitterclone.ErrNotFound) {
		return twitterclone.AuthResponse{}, twitterclone.ErrEmailTaken
	}

	//Create the User

	user := twitterclone.User{
		Email:    input.Email,
		Username: input.Username,
	}

	//Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error hashing password: %v", err)
	}
	user.Password = string(hashPassword)

	user, err = as.UserRepo.Create(ctx, user)

	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error creating user: %v", err)
	}

	//Return access token and user
	return twitterclone.AuthResponse{
		AccessToken: "a token",
		User:        user,
	}, nil
}
