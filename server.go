package main

import (
	"github.com/codegangsta/negroni"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/config"
	"github.com/leo-backend/routers"
	"log"
	"net/http"
)

func main() {
	log.Println("Starting up server.")
	// Initializes routes and creates a negroni instance to handle them
	router := routers.InitRoutes()
	n := negroni.New()
	recovery := negroni.NewRecovery()
	recovery.PrintStack = false
	n.Use(recovery)
	n.Use(negroni.NewLogger())
	n.UseHandler(router)

	// Setup db and make it close on exit
	backend.InitDB()
	backend.StartPurgeEntriesTask()
	defer backend.StopPurgeEntriesTask()
	defer backend.CloseDB()

	if config.ShouldUseTLS {
		http.ListenAndServeTLS(":5000", config.CertificatePath,
			config.TLSPrivateKeyPath, n)
	} else {
		http.ListenAndServe(":5000", n)
	}
}
