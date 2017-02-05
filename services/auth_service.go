package services

import (
	"encoding/json"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/leo-backend/api/parameters"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/services/models"
	"log"
	"net/http"
)

func Login(requestUser *models.User) (int, []byte) {
	authBackend := backend.InitJWTAuthenticationBackend()

	if authBackend.Authenticate(requestUser) {
		token, err := authBackend.GenerateToken(requestUser.UUID)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			response, _ := json.Marshal(parameters.TokenAuthentication{token})
			return http.StatusOK, response
		}
	}

	return http.StatusUnauthorized, []byte("")
}

func RefreshToken(requestUser *models.User) []byte {
	authBackend := backend.InitJWTAuthenticationBackend()
	token, err := authBackend.GenerateToken(requestUser.UUID)
	if err != nil {
		panic(err)
	}
	response, err := json.Marshal(parameters.TokenAuthentication{token})
	if err != nil {
		panic(err)
	}
	return response
}

func Logout(requestUser *models.User, req *http.Request) error {
	authBackend := backend.InitJWTAuthenticationBackend()
	tokenRequest, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return authBackend.PublicKey, nil
	})
	if err != nil {
		return err
	}
	tokenString := req.Header.Get("Authorization")
	return authBackend.Logout(requestUser, tokenString, tokenRequest)
}

func GetUser(requestUser *models.User) (int, []byte) {
	authBackend := backend.InitJWTAuthenticationBackend()
	if authBackend.GetUser(requestUser) != nil {
		// at this point we have
		token, err := authBackend.GenerateToken(requestUser.UUID)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			response, _ := json.Marshal(parameters.TokenAuthentication{token})
			return http.StatusOK, response
		}
	}
	return http.StatusUnauthorized, []byte("")
}

func CreateUser(requestUser *models.User) (int, []byte) {
	authBackend := backend.InitJWTAuthenticationBackend()
	err := authBackend.CreateUser(requestUser)

	if err != nil {
		log.Println("Could not register user.")
		return http.StatusUnauthorized, []byte("")
	}

	token, err := authBackend.GenerateToken(requestUser.UUID)
	if err != nil {
		return http.StatusInternalServerError, []byte("")
	}

	response, _ := json.Marshal(parameters.TokenAuthentication{token})
	log.Println("Successfully registered user.")
	return http.StatusOK, response

}
