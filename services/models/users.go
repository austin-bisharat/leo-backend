package models

import (
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type IPData struct {
	Username 	string 	`json:"username:`
	IP 		string 	`json:"ip"`
	Port 	string 	`json:"port"`
	PubKey  string 	`json:"pubkey"`
	TimeStamp time.Time `json:"update-time"`
}