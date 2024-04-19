package main

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JWT_KEY = "secret_key"
const JWT_DURATION_IN_SECONDS = 120
const JWT_COOKIE_NAME = "Bearer"

type LoginPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type UserResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var payload LoginPayload
	err := ReadJSON(w, r, &payload)
	if err != nil {
		ErrorJSON(w, err, http.StatusUnprocessableEntity)
		return
	}

	var response JsonResponse

	user, err := getUserByEmailAndPassword(payload.Email, payload.Password)
	if err != nil {
		response.Error = true
		response.Message = "Invalid email or password"
		WriteJSON(w, http.StatusBadRequest, response)
		return
	}

	token, err := createJwtToken(user)
	if err != nil {
		log.Panic(err)
		response.Error = true
		response.Message = "Oops, something went wrong!"
		WriteJSON(w, http.StatusBadRequest, response)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Value:    token,
		Name:     JWT_COOKIE_NAME,
		HttpOnly: true,
	})
	response.Error = false
	response.Message = "ok"
	response.Data = LoginResponse{
		Token: token,
	}
	WriteJSON(w, http.StatusOK, response)
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	authInfo := r.Context().Value(ContextAuthInfoKey).(AuthInfo)

	user, err := getUserById(authInfo.UserId)

	var response JsonResponse
	if err != nil {
		response.Error = true
		response.Message = "Not found"
	} else {
		response.Error = false
		response.Message = "ok"
		response.Data = UserResponse{
			Id:    user.Id,
			Email: user.Email,
		}
	}

	WriteJSON(w, http.StatusOK, response)
}

func getUserByEmailAndPassword(email string, password string) (UserDto, error) {
	for _, user := range Users {
		if user.Email == email && user.Password == password {
			return user, nil
		}
	}

	return UserDto{}, errors.New("user not found")
}

func getUserById(userId int) (UserDto, error) {
	for _, user := range Users {
		if user.Id == userId {
			return user, nil
		}
	}

	return UserDto{}, errors.New("user not found")
}

type Claims struct {
	UserId int `json:"userId"`
	jwt.RegisteredClaims
}

func createJwtToken(user UserDto) (string, error) {
	claims := &Claims{
		UserId: user.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_DURATION_IN_SECONDS * time.Second)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(JWT_KEY))
}
