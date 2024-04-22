package main

import (
	"context"
	"errors"
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
		accessTokenCookie, err := r.Cookie(JWT_ACCESS_TOKEN_NAME)
		if err != nil {
			log.Print("Error accessing access token cookie: ", err)
			UnauthorizedResponse(w)
			return
		}

		refreshTokenCookie, err := r.Cookie(JWT_REFRESH_TOKEN_NAME)
		if err != nil {
			log.Print("Error accessing refresh token cookie: ", err)
			UnauthorizedResponse(w)
			return
		}

		accessTokenString := accessTokenCookie.Value

		accessTokenClaims := &Claims{}
		accessToken, err := jwt.ParseWithClaims(accessTokenString, accessTokenClaims, func(token *jwt.Token) (any, error) {
			return []byte(JWT_ACCESS_TOKEN_KEY), nil
		})

		if err != nil {
			if isErrorTokenExpired(err) {
				log.Print("Token is expired, refreshing...")
				refreshTokenString := refreshTokenCookie.Value
				refreshTokenClaims := &Claims{}
				refreshToken, err := jwt.ParseWithClaims(refreshTokenString, refreshTokenClaims, func(token *jwt.Token) (any, error) {
					return []byte(JWT_REFRESH_TOKEN_KEY), nil
				})

				if err != nil {
					if isErrorTokenExpired(err) {
						log.Print("Refersh token expired: ", err)
					} else {
						log.Print("Error decoding refresh token: ", err)
					}

					UnauthorizedResponse(w)
					return
				}

				if refreshToken.Valid {
					userId := accessTokenClaims.UserId

					err := AuthenticateById(w, userId)

					if err != nil {
						log.Print(err)
						UnauthorizedResponse(w)
						return
					}

					ctx := context.WithValue(r.Context(), ContextAuthInfoKey, AuthInfo{
						UserId: userId,
					})
					next.ServeHTTP(w, r.WithContext(ctx))

					return
				} else {
					log.Print("Invalid token: ", err)
					UnauthorizedResponse(w)
					return
				}
			}

			log.Print("Invalid access token: ", err)
			UnauthorizedResponse(w)
			return
		}

		if accessToken.Valid {
			ctx := context.WithValue(r.Context(), ContextAuthInfoKey, AuthInfo{
				UserId: accessTokenClaims.UserId,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			log.Print("Invalid token: ", err)
			UnauthorizedResponse(w)
			return
		}
	})
}

func isErrorTokenExpired(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
