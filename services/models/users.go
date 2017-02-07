package models

import (
	"time"
)

type User struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type IPData struct {
	UUID 	string 	`json:"uuid:`
	IP 		string 	`json:"ip"`
	Port 	string 	`json:"port"`
	PubKey  string 	`json:"pubkey"`
	TimeStamp time.Time `json:"update-time"`
}
