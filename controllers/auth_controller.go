package controllers

import (
	"encoding/json"
	"github.com/leo-backend/services"
	"github.com/leo-backend/services/models"
	"io/ioutil"
	"net/http"
	"log"
)

func Login(w http.ResponseWriter, r *http.Request) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestUser)

	responseStatus, token := services.Login(requestUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseStatus)
	w.Write(token)
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestUser)

	w.Header().Set("Content-Type", "application/json")
	w.Write(services.RefreshToken(requestUser))
}

func Logout(w http.ResponseWriter, r *http.Request) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestUser)

	responseStatus := services.Logout(requestUser, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseStatus)
}

// We expect r.body to contain a serialized JSON object of the following form:
// { "message": "<encrypt({"username":"<username"})>" }.
// There is an extra layer of indirection in order to more easily support changing
// the API to do batching, which would require an array of the above objects,
// each with a uuid field.
func GetUser(w http.ResponseWriter, r *http.Request) {

	// responseBody is either an error, or a string of a json object
	// of the following form:
	//    { "user_ip": "<ip>", "user_pub_key": "<pem format pub key PKCS8>" }
	body, _ := ioutil.ReadAll(r.Body)

	responseStatus, responseBody := services.GetUser(body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseStatus)
	w.Write(responseBody)
}

func Update(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	requestUser := new(models.User)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestUser)

	responseStatus, token := services.CreateUser(requestUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseStatus)
	w.Write(token)
}

func Register(w http.ResponseWriter, r *http.Request) {
	requestIP := new(models.IPData)
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&requestIP)

	responseStatus, data := services.Register(requestIP, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(responseStatus)
	w.Write(data)
}
