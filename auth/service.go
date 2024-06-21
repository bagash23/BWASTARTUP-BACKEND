package auth

import (
	"errors"
	"os"

	"github.com/dgrijalva/jwt-go"
)

type Service interface {
	GeneratedToken(userID int)(string, error)
	ValidateToken(encodedToken string)(*jwt.Token, error)
}

type jwtService struct {
    
}

func NewService() *jwtService {
	return &jwtService{}
}
var SECRET_KEY = []byte(os.Getenv("KEY_SECRET"))

func (s *jwtService) GeneratedToken(userID int)(string, error) {
	claim := jwt.MapClaims{}
	claim["user_id"] = userID

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString,err := token.SignedString(SECRET_KEY)
	if err != nil {
        return tokenString, err
    }

    return tokenString, nil
}


func (s *jwtService) ValidateToken(encodedToken string)(*jwt.Token, error) {
	token, err := jwt.Parse(encodedToken, func(t *jwt.Token) (interface{}, error) {
		_, ok := t.Method.(*jwt.SigningMethodHMAC) 

		if !ok {
			return nil, errors.New("Invalid token")
		}

		return []byte(SECRET_KEY), nil
	})
	if err != nil {
		return token, err
	}

	return token, nil
}