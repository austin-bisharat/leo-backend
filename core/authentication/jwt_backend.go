package authentication

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/bobintornado/boltdb-boilerplate"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/leo-backend/core/redis"
	"github.com/leo-backend/services/models"
	"github.com/leo-backend/settings"
	"golang.org/x/crypto/bcrypt"
	"os"
	"log"
	"time"
)

// TODO change this all to bolt db
type JWTAuthenticationBackend struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

const (
	tokenDuration = 72
	expireOffset  = 3600
)

var authBackendInstance *JWTAuthenticationBackend = nil

func InitJWTAuthenticationBackend() *JWTAuthenticationBackend {
	if authBackendInstance == nil {
		authBackendInstance = &JWTAuthenticationBackend{
			privateKey: getPrivateKey(),
			PublicKey:  getPublicKey(),
		}
	}

	return authBackendInstance
}

func (backend *JWTAuthenticationBackend) GenerateToken(userUUID string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS512)
	token.Claims = jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * time.Duration(settings.Get().JWTExpirationDelta)).Unix(),
		"iat": time.Now().Unix(),
		"sub": userUUID,
	}

	//
	tokenString, err := token.SignedString(backend.privateKey)
	if err != nil {
		panic(err)
		return "", err
	}
	return tokenString, nil
}

func (backend *JWTAuthenticationBackend) Authenticate(user *models.User) bool {
	// Obtain hashed password from DB
	value := boltdbboilerplate.Get([]byte("userpassword"), []byte(user.Username))
	// https://godoc.org/golang.org/x/crypto/bcrypt
	return bcrypt.CompareHashAndPassword(value, []byte(user.Password)) == nil
}

func (backend *JWTAuthenticationBackend) getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(validity), 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int(remainer.Seconds() + expireOffset)
		}
	}
	return expireOffset
}

func (backend *JWTAuthenticationBackend) Logout(tokenString string, token *jwt.Token) error {
	redisConn := redis.Connect()
	// TODO more backend stuff
	return redisConn.SetValue(tokenString, tokenString, backend.getTokenRemainingValidity(token.Claims.(jwt.MapClaims)["exp"]))
}

func (backend *JWTAuthenticationBackend) GetUser(user *models.User) []byte {
	value := boltdbboilerplate.Get([]byte("ipaddress"), []byte(user.Username))
	return value
}

func (backend *JWTAuthenticationBackend) RegisterUser(user *models.User) error {
	// TODO this conversion may be incorrect
	byteArray := []byte(user.Password)
	log.Println(user.Password)
	res, err := bcrypt.GenerateFromPassword(byteArray, 100)

	err = boltdbboilerplate.Put([]byte("userpassword"), []byte(user.Username), res)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("Registered user")
	return nil
}

func getPrivateKey() *rsa.PrivateKey {
	privateKeyFile, err := os.Open(settings.Get().PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	// There is something going wrong in this line, trying to figure it out
	privateKeyImported, err := x509.ParsePKCS8PrivateKey(data.Bytes)

	if err != nil {
		panic(err)
	}
	rsa, ok := privateKeyImported.(*rsa.PrivateKey)
	if !ok {
		panic(ok)
	}
	return rsa
}

func getPublicKey() *rsa.PublicKey {
	publicKeyFile, err := os.Open(settings.Get().PublicKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)

	if !ok {
		panic(err)
	}

	return rsaPub
}
