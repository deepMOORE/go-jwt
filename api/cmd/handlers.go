package main

import (
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JWT_ACCESS_TOKEN_KEY = "secret_key"
const JWT_ACCESS_TOKEN_DURATION_IN_SECONDS = 5 // 5 seconds
const JWT_ACCESS_TOKEN_NAME = "Access"

const JWT_REFRESH_TOKEN_KEY = "key_secret"
const JWT_REFRESH_TOKEN_DURATION_IN_SECONDS = 2592000 // 1 month
const JWT_REFRESH_TOKEN_NAME = "Refresh"

type LoginPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

	user, err := GetUserByEmailAndPassword(payload.Email, payload.Password)
	if err != nil {
		response.Error = true
		response.Message = "Invalid email or password"
		WriteJSON(w, http.StatusBadRequest, response)
		return
	}

	err = authenticateToSetTokens(w, user)

	if err != nil {
		log.Print("something went wrong")
		response.Error = true
		response.Message = "Invalid email or password"
		WriteJSON(w, http.StatusBadRequest, response)
		return
	}

	response.Error = false
	response.Message = "ok"

	WriteJSON(w, http.StatusOK, response)
}

func AuthenticateById(w http.ResponseWriter, userId int) error {
	user, err := GetUserById(userId)
	if err != nil {
		return err
	}

	return authenticateToSetTokens(w, user)
}

func authenticateToSetTokens(w http.ResponseWriter, user UserDto) error {
	accessToken, refreshToken, err := createTokenPair(user)

	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Value:    accessToken,
		Name:     JWT_ACCESS_TOKEN_NAME,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Value:    refreshToken,
		Name:     JWT_REFRESH_TOKEN_NAME,
		HttpOnly: true,
	})

	return nil
}

func createTokenPair(user UserDto) (string, string, error) {
	accessToken, err := createAccessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := createRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, err
}

func GetUser(w http.ResponseWriter, r *http.Request) {
	authInfo := r.Context().Value(ContextAuthInfoKey).(AuthInfo)

	user, err := GetUserById(authInfo.UserId)

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

type Claims struct {
	UserId int `json:"userId"`
	jwt.RegisteredClaims
}

func createAccessToken(user UserDto) (string, error) {
	claims := &Claims{
		UserId: user.Id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_ACCESS_TOKEN_DURATION_IN_SECONDS * time.Second)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(JWT_ACCESS_TOKEN_KEY))
}

func createRefreshToken() (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(JWT_REFRESH_TOKEN_DURATION_IN_SECONDS * time.Second)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(JWT_REFRESH_TOKEN_KEY))
}
