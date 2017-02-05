package main

import (
	"github.com/codegangsta/negroni"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/routers"
	"github.com/leo-backend/settings"
	"log"
	"net/http"
)

func main() {
	settings.Init()
	log.Println("Starting up server.")
	// Initializes routes and creates a negroni instance to handle them
	router := routers.InitRoutes()
	n := negroni.Classic()
	n.UseHandler(router)

	// Setup db and make it close on exit
	backend.InitDB()
	defer backend.CloseDB()

	// TODO make this HTTPs
	http.ListenAndServe(":5000", n)
}
