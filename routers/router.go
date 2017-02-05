package routers

import (
	"github.com/gorilla/mux"
	"github.com/leo-backend/controllers"
)

func InitRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/login", controllers.Login).Methods("POST")
	router.HandleFunc("/refresh-token-auth", controllers.RefreshToken).Methods("GET")
	router.HandleFunc("/logout", controllers.Logout).Methods("POST")
	router.HandleFunc("/user", controllers.GetUser).Methods("POST")
	router.HandleFunc("/create-user", controllers.CreateUser).Methods("POST")
	router.HandleFunc("/hello", controllers.HelloController).Methods("GET")
	return router
}
