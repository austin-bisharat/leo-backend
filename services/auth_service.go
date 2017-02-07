package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/leo-backend/api/parameters"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/services/models"
	"log"
	"net/http"
	"time"
)

func Login(requestUser *models.User) (int, []byte) {
	authBackend := backend.InitJWTAuthenticationBackend()

	if authBackend.Authenticate(requestUser) {
		token, err := authBackend.GenerateToken(requestUser.Username)
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
	token, err := authBackend.GenerateToken(requestUser.Username)
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
	tokenString, err := requireAuth(requestUser.Username, req)
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

	err = json.Unmarshal([]byte(messageString), &f)
	if err != nil {
		return http.StatusNotFound, []byte("")
	}
	m = f.(map[string]interface{})
	username := m["username"].(string)
	pubKeyString := m["pub_key"].(string)

	var pubKey *rsa.PublicKey
	pubKey, err = parsePubKey(pubKeyString)
	if err != nil {
		return http.StatusNotFound, []byte("")
	}

	// Replace with model
	recipient := backend.GetUserIP(username)
	if recipient == nil {
		return http.StatusNotFound, []byte("")
	}
	recipientMap := map[string]string{
		"user_ip":   recipient.IP,
		"user_port": recipient.Port,
		"pub_key":   recipient.PubKey,
	}

	toSign := recipientMap["user_ip"] + recipientMap["user_port"] + recipientMap["pub_key"]
	var signature []byte
	signature, err = authBackend.SignString(toSign)
	if err != nil {
		return http.StatusNotFound, []byte("")
	}
	recipientMap["signature"] = b64.StdEncoding.EncodeToString(signature)

	var userInfo []byte
	userInfo, err = json.Marshal(recipientMap)
	if err != nil {
		return http.StatusNotFound, []byte("")
	}

	ciphertexts := []string{}
	messages := splitSubN(string(userInfo), 100)
	for _, m := range messages {
		var ciphertext []byte
		ciphertext, err = rsa.EncryptOAEP(sha1.New(), rand.Reader,
			pubKey, []byte(m), []byte(""))
		if err != nil {
			log.Println("Error encrypting")
			log.Println(err)
			return http.StatusNotFound, []byte("")
		}
		c := b64.StdEncoding.EncodeToString(ciphertext)
		ciphertexts = append(ciphertexts, c)
	}

	messageMap := map[string][]string{
		"message": ciphertexts,
	}

	var resp []byte
	resp, err = json.Marshal(messageMap)

	if err != nil {
		return http.StatusNotFound, []byte("")
	}

	return http.StatusOK, resp
}

func splitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	l := len(s)
	for i, r := range s {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

func parsePubKey(pubKeyString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyString))
	if block == nil {
		return nil, errors.New("Couldn't read pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Couldn't read pem")
	}
	return pub.(*rsa.PublicKey), nil
}

func CreateUser(requestUser *models.User) (int, []byte) {
	authBackend := backend.InitJWTAuthenticationBackend()
	err := authBackend.CreateUser(requestUser)

	if err != nil {
		log.Println("Could not register user.")
		return http.StatusUnauthorized, []byte("")
	}

	token, err := authBackend.GenerateToken(requestUser.Username)
	if err != nil {
		return http.StatusInternalServerError, []byte("")
	}

	response, _ := json.Marshal(parameters.TokenAuthentication{token})
	log.Println("Successfully registered user.")
	return http.StatusOK, response
}

func Register(requestIP *models.IPData, req *http.Request) (int, []byte) {
	// First verify the user is authorized.
	_, err := requireAuth(requestIP.Username, req)
	if err != nil {
		return http.StatusUnauthorized, []byte("")
	}

	log.Println(requestIP)
	// TODO should we require that data bve in the requestIP?
	if requestIP.IP == ""  || requestIP.Port == "" || requestIP.PubKey == "" {
		return http.StatusBadRequest, []byte("")
	}

	// Next, take the IPData and place it in the backend.
	requestIP.TimeStamp = time.Now()
	backend.SetUserIP(requestIP.Username, requestIP)
	// TODO figure out if we should return anything here.
	return http.StatusOK, []byte("")
}

// private method for requiring auth
func requireAuth(username string, req *http.Request) (string, error) {
	authBackend := backend.InitJWTAuthenticationBackend()
	log.Println("Trying to verify token")
	token, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			return authBackend.PublicKey, nil
		}
	})
	if err != nil || !token.Valid {
		return "", err
	}
	tokenString := req.Header.Get("Authorization")
	log.Println(tokenString)
	
	log.Println("Checking if token is in db.")
	return tokenString, authBackend.RequireTokenAuthentication(username, tokenString)
}
