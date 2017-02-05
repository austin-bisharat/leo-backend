package routers

import (
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/leo-backend/backend"
	"github.com/leo-backend/controllers"
)

func InitRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/login", controllers.Login).Methods("POST")
	router.Handle("/refresh-token-auth",
		negroni.New(
			negroni.HandlerFunc(backend.RequireTokenAuthentication),
			negroni.HandlerFunc(controllers.RefreshToken),
		)).Methods("GET")
	router.Handle("/logout",
		negroni.New(
			negroni.HandlerFunc(backend.RequireTokenAuthentication),
			negroni.HandlerFunc(controllers.Logout),
		)).Methods("POST")
	router.HandleFunc("/user", controllers.GetUser).Methods("POST")
	router.HandleFunc("/create-user", controllers.CreateUser).Methods("POST")
	router.HandleFunc("/hello", controllers.HelloController).Methods("GET")
	return router
}
