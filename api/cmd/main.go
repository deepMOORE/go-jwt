package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
)

const apiPort = 8080

var Users []UserDto

type UserDto struct {
	Id       int
	Email    string
	Password string
}

type RequestPayload struct {
	Data string `json:"data,omitempty"`
}

func main() {
	Users = append(Users, UserDto{
		Id:       11,
		Email:    "qwe",
		Password: "qwe",
	})
	Users = append(Users, UserDto{
		Id:       22,
		Email:    "asd",
		Password: "asd",
	})

	mux := chi.NewRouter()
	mux.Use(middleware.Logger)
	mux.Use(cors.Handler(cors.Options{
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedOrigins: []string{"https://*", "http://*"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
	}))

	mux.Route("/api", func(mux chi.Router) {
		mux.Post("/login", Login)
		mux.Route("/", func(mux chi.Router) {
			mux.Use(JwtAuthMiddleware)
			mux.Get("/user", GetUser)
		})
	})

	fmt.Printf("Starting listening on port %d\n", apiPort)
	err := http.ListenAndServe(fmt.Sprintf(":%d", apiPort), mux)
	if err != nil {
		log.Panic(err)
	}
}
