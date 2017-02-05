package services

import (
	b64 "encoding/base64"
	"encoding/json"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/leo-backend/api/parameters"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/services/models"
	"log"
	"net/http"
	"fmt"
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

// TODO maybe add a []byte to the response
func Logout(requestUser *models.User, req *http.Request) int {
	authBackend := backend.InitJWTAuthenticationBackend()
	tokenString, err := requireAuth(requestUser, req)
	if err != nil {
		return http.StatusUnauthorized
	}

	err = authBackend.Logout(requestUser, tokenString)
	if err != nil {
		return http.StatusInternalServerError
	}

	return http.StatusOK
}

func GetUser(body []byte) (int, []byte) {
	// First, we extract the "message" field from the body
	var f interface{}
	err := json.Unmarshal(body, &f)
	log.Println(string(body))
	if err != nil {
		return http.StatusNotFound, []byte("")
	}
	m := f.(map[string]interface{})
	f = m["message"]
	encryptedMessageArr := f.([]interface{})
	if encryptedMessageArr == nil {
		return http.StatusNotFound, []byte("")
	}

	// Next, we decrypt that message field using our private key
	authBackend := backend.InitJWTAuthenticationBackend()
	messageString := ""
	for _, ciphertext := range encryptedMessageArr {
		var cipherBytes []byte
		cipherBytes, err = b64.StdEncoding.DecodeString(ciphertext.(string))
		var plaintext []byte
		plaintext, err = authBackend.DecryptCiphertext(cipherBytes)
		if err != nil {
			return http.StatusNotFound, []byte("")
		}
		messageString = messageString + string(plaintext)
	}
	log.Println("==============================")
	log.Println(messageString)

	if err != nil {
		return http.StatusNotFound, []byte("")
	}
	return http.StatusOK, nil
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

// private method for requiring auth
func requireAuth(requestUser *models.User, req *http.Request) (string, error) {
	authBackend := backend.InitJWTAuthenticationBackend()
	log.Println("Trying to verify token")
	token, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			return authBackend.PublicKey, nil
		}
	})
	log.Println("Obtained token")
	log.Println(token.Valid)
	if err != nil || !token.Valid {
		return "", err
	}
	tokenString := req.Header.Get("Authorization")
	log.Println("Checking if token is in db.")
	return tokenString, authBackend.RequireTokenAuthentication(requestUser, tokenString)
}