package main

import (
	"context"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type AuthInfo struct {
	UserId int
}
type ContextKey string

const ContextAuthInfoKey ContextKey = "authInfo"

func JwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(JWT_COOKIE_NAME)
		if err != nil {
			log.Print("Error accessing cookie: ", err)
			UnauthorizedResponse(w)
			return
		}

		tokenString := cookie.Value

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return []byte(JWT_KEY), nil
		})

		if err != nil {
			log.Print("Error decoding token: ", err)
			UnauthorizedResponse(w)
			return
		}

		if token.Valid {
			ctx := context.WithValue(r.Context(), ContextAuthInfoKey, AuthInfo{
				UserId: claims.UserId,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			log.Print("Invalid token: ", err)
			UnauthorizedResponse(w)
			return
		}
	})
}
