package models

import (
	"time"
)

type User struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type Token struct {
	Token    string `json:token`
	Created time.Time `json:created`
}
