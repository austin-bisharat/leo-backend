package routers

import (
	"github.com/gorilla/mux"
	"github.com/leo-backend/controllers"
)

func InitRoutes() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/login", controllers.Login).Methods("POST")
	router.HandleFunc("/refresh_token_auth", controllers.RefreshToken).Methods("GET")
	router.HandleFunc("/logout", controllers.Logout).Methods("POST")
	router.HandleFunc("/get_user", controllers.GetUser).Methods("POST")
	router.HandleFunc("/create_user", controllers.CreateUser).Methods("POST")
	router.HandleFunc("/hello", controllers.HelloController).Methods("GET")
	router.HandleFunc("/register", controllers.Register).Methods("POST")
	router.HandleFunc("/coming_for_that_booty", controllers.Register).Methods("POST")

	return router
}
