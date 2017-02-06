package backend

import (
    "sync"
    "time"
    "github.com/leo-backend/services/models"
)

var m map[string]*models.IPData = make(map[string]*models.IPData)
var lock = &sync.Mutex{}
const (

	TIME_TO_PURGE float64 = 10.0
)

func Get(key string) (*models.IPData){
	lock.Lock()
	val := m[key]
	lock.Unlock()
	return val
}

func Set(key string, value *models.IPData) {
	lock.Lock()
	m[key] = value
	lock.Unlock()
}

func PurgeEntries() {
	lock.Lock()
	for key, value := range m {
	    if time.Now().Sub(value.TimeStamp).Minutes() > TIME_TO_PURGE {
	    	delete(m, key)
	    }
	}
	lock.Unlock()
}
