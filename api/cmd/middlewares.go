package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type AuthInfo struct {
	UserId int
}
type ContextKey string

const ContextAuthInfoKey ContextKey = "authInfo"

func JwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			log.Print("Header is empty")
			UnauthorizedResponse(w)
			return
		}

		parts := strings.Split(strings.TrimSpace(authorizationHeader), " ")

		if len(parts) != 2 || parts[0] != TOKEN_TYPE {
			log.Printf("Parts is incorrect")
			log.Print(parts)
			UnauthorizedResponse(w)
			return
		}

		tokenString := parts[1]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return []byte(JWT_KEY), nil
		})

		if err != nil {
			log.Printf("Error decoding token")
			log.Print(err)
			UnauthorizedResponse(w)
			return
		}

		if token.Valid {
			ctx := context.WithValue(r.Context(), ContextAuthInfoKey, AuthInfo{
				UserId: claims.UserId,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
