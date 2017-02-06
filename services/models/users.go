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
	IP []byte `json:"ip"`
	Port int `json:port`
	PubKey []byte `json:pubkey`
	TimeStamp time.Time `json:update-time`
}
