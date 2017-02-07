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
	IP 		string 	`json:"user_ip"`
	Port 	string 	`json:"user_port"`
	PubKey  string 	`json:"user_pub_key"`
	TimeStamp time.Time `json:"update_time"`
}