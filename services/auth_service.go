package services

import (
	"encoding/json"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/leo-backend/api/parameters"
	"github.com/leo-backend/core/authentication"
	"github.com/leo-backend/log"
	"github.com/leo-backend/services/models"
	"net/http"
)

func Login(requestUser *models.User) (int, []byte) {
	authBackend := authentication.InitJWTAuthenticationBackend()

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
	authBackend := authentication.InitJWTAuthenticationBackend()
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

func Logout(req *http.Request) error {
	authBackend := authentication.InitJWTAuthenticationBackend()
	tokenRequest, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return authBackend.PublicKey, nil
	})
	if err != nil {
		return err
	}
	tokenString := req.Header.Get("Authorization")
	return authBackend.Logout(tokenString, tokenRequest)
}

func GetUser(requestUser *models.User) (int, []byte) {
	authBackend := authentication.InitJWTAuthenticationBackend()
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

func Register(requestUser *models.User) (int, []byte) {
	authBackend := authentication.InitJWTAuthenticationBackend()
	if authBackend.RegisterUser(requestUser) != nil {
		token, err := authBackend.GenerateToken(requestUser.UUID)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			log.Debug("here")
			response, _ := json.Marshal(parameters.TokenAuthentication{token})
			return http.StatusOK, response
		}
	}
	return http.StatusUnauthorized, []byte("")
}
