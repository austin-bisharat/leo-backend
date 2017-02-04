package routers

import (
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/leo-backend/controllers"
	"github.com/leo-backend/core/authentication"
)

func InitRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/login", controllers.Login).Methods("POST")
	router.Handle("/refresh-token-auth",
		negroni.New(
			negroni.HandlerFunc(authentication.RequireTokenAuthentication),
			negroni.HandlerFunc(controllers.RefreshToken),
		)).Methods("GET")
	router.Handle("/logout",
		negroni.New(
			negroni.HandlerFunc(authentication.RequireTokenAuthentication),
			negroni.HandlerFunc(controllers.Logout),
		)).Methods("GET")
	router.HandleFunc("/user", controllers.GetUser).Methods("POST")
	router.HandleFunc("/register", controllers.Register).Methods("POST")
	router.HandleFunc("/hello", controllers.HelloController).Methods("GET")
	return router
}
