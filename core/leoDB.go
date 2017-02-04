package authentication;
import (
	"fmt"
	"os"
	"github.com/boltdb/bolt"
)

type DB struct {
	*bolt.DB
}
