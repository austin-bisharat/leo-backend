package backend

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/leo-backend/services/models"
	"github.com/leo-backend/settings"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
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

var db *bolt.DB = nil
func InitDB() error {
	newDB, err := bolt.Open("leo.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	db = newDB
	if err != nil {
		panic("Cannot open db")
		return err
	}

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte("userpassword"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		_, err = tx.CreateBucket([]byte("ipaddress"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		_, err = tx.CreateBucket([]byte("tokens")) // username => token
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		log.Println("Added tokens bucket to db")

		return nil
	})
	return nil
}

func CloseDB() {
	db.Close()
}

func InitJWTAuthenticationBackend() *JWTAuthenticationBackend {
	if authBackendInstance == nil {
		authBackendInstance = &JWTAuthenticationBackend{
			privateKey: getPrivateKey(),
			PublicKey:  getPublicKey(),
		}
	}

	return authBackendInstance
}

// Given a byte array, decrypt using this backend's private key
func (backend *JWTAuthenticationBackend) DecryptCiphertext(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, backend.privateKey,
		ciphertext, []byte(""))
}

// Given a string, sign it using private key
func (backend *JWTAuthenticationBackend) SignString(toSign string) ([]byte, error) {
	hashed := sha256.Sum256([]byte(toSign))
	return rsa.SignPKCS1v15(rand.Reader, backend.privateKey,
		crypto.SHA256, hashed[:])
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

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		err := b.Put([]byte(userUUID), []byte(tokenString))
		if err != nil {
			return errors.New("User already exists")
		}
		return nil
	})

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (backend *JWTAuthenticationBackend) Authenticate(user *models.User) bool {
	// Obtain hashed password from DB
	var hashedPassword []byte
	log.Println("Autheticating user.")
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("userpassword"))
		v := b.Get([]byte(user.Username))
		if v == nil {
			return errors.New("User does not exist, create user first.")
		}
		log.Println("Obtained user!")
		hashedPassword = v
		return nil
	})
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(user.Password)) == nil

}

func (backend *JWTAuthenticationBackend) Logout(user *models.User, tokenString string) error {
	// Deletes token from DB
	err := db.Update(func(tx *bolt.Tx) error {
		log.Println("Trying to delete token")
		b := tx.Bucket([]byte("tokens"))
		err := b.Delete([]byte(user.UUID))
		log.Println(err)
		if err != nil {
			return err
		}
		return nil
	})
	// TODO unregister the user from the timestamp_map too
	return err
}

// Gets the ip and pub key for the given user
func (backend *JWTAuthenticationBackend) GetUser(user *models.User) ([]byte, error) {
	var value []byte
	// There is no need for this bucket.
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("ipaddress"))
		if b == nil {
			panic("No ipaddress bucket")
		}
		// TODO, change this to lookup in global map. Also should validate by time
		value = b.Get([]byte(user.Username))
		if value == nil {
			return errors.New("No such user")
		}
		return nil
	})
	return value, err
}

func (backend *JWTAuthenticationBackend) CreateUser(user *models.User) error {
	// TODO this conversion may be incorrect
	byteArray := []byte(user.Password)
	log.Println(user.Password)
	res, err := bcrypt.GenerateFromPassword(byteArray, 4)
	if err != nil {
		log.Println(err)
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("userpassword"))
		v := b.Get([]byte(user.Username))
		log.Println(v)
		if v != nil {
			return errors.New("User already exists")
		}
		err := b.Put([]byte(user.Username), res)
		return err
	})
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println("Registered user")
	return nil
}

func (backend *JWTAuthenticationBackend) Register(user *models.User, requestIP *models.IPData) error {
	// put it in the mapping
	requestIP.TimeStamp = time.Now()
	Set(user.UUID, requestIP)

	return nil
}

func (backend *JWTAuthenticationBackend) RequireTokenAuthentication(user *models.User, tokenString string) error {

	var storedToken []byte

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		v := b.Get([]byte(user.UUID))
		storedToken = v
		return nil
	})
	if tokenString != string(storedToken) {
		return fmt.Errorf("User is not logged in. Sign in again to perform that action.")
	}
	if storedToken == nil || err != nil {
		return fmt.Errorf("User is not logged in. Sign in again to perform that action.")
	}
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
