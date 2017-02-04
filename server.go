package main

import (
	"github.com/bobintornado/boltdb-boilerplate"
	"github.com/codegangsta/negroni"
	"github.com/leo-backend/log"
	"github.com/leo-backend/routers"
	"github.com/leo-backend/settings"
	"net/http"
)

func main() {
	settings.Init()

	log.InitLog()

	// Initializes routes and creates a negroni instance to handle them
	router := routers.InitRoutes()
	n := negroni.Classic()
	n.UseHandler(router)

	// Uses a boilerplate for querying boltdb
	// Much easier to use than dealing with transactions.
	buckets := []string{"ipaddress", "userpassword"}

	err := boltdbboilerplate.InitBolt("./leoDB.db", buckets)
	if err != nil {
		panic("cannot open DB")
	}

	defer boltdbboilerplate.Close()

	// TODO make this HTTPs
	http.ListenAndServe(":5000", n)
}
