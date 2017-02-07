package backend

import (
	"github.com/leo-backend/services/models"
	"sync"
	"time"
)

var m map[string]*models.IPData = make(map[string]*models.IPData)
var lock = &sync.Mutex{}
var shouldStopPurgeTask = false

const (
	// Represents the number of minutes before an entry is considered invalid
	TIME_TO_PURGE float64 = 2.0

	// Represents how frequently purging actually occurs
	PURGE_FREQUENCY time.Duration = 10
)

func GetUserIP(key string) *models.IPData {
	lock.Lock()
	val := m[key]
	if time.Now().Sub(val.TimeStamp).Minutes() > TIME_TO_PURGE {
		delete(m, key)
		val = nil
	}
	lock.Unlock()
	return val
}

func SetUserIP(key string, value *models.IPData) {
	lock.Lock()
	m[key] = value
	lock.Unlock()
}

func purgeEntries() {
	lock.Lock()
	for key, value := range m {
		if time.Now().Sub(value.TimeStamp).Minutes() > TIME_TO_PURGE {
			delete(m, key)
		}
	}
	lock.Unlock()
}

func StartPurgeEntriesTask() {
	shouldStopPurgeTask = false
	go func() {
		for {
			if shouldStopPurgeTask {
				return
			}
			purgeEntries()
			time.Sleep(PURGE_FREQUENCY * time.Second)
		}
	}()
}

func StopPurgeEntriesTask() {
	shouldStopPurgeTask = true
}
