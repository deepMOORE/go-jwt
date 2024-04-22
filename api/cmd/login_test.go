package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestShouldLogin(t *testing.T) {
	Users = append(Users, UserDto{
		Email:    "qwe",
		Password: "qwe",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/login", toRequestBody(
		map[string]any{"email": "qwe", "password": "qwe"},
	))

	w := httptest.NewRecorder()

	Login(w, request)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d. Got %d", http.StatusOK, w.Code)
	}

	resBody := make(map[string]any)
	json.NewDecoder(w.Body).Decode(&resBody)
	expectedRes := map[string]any{"error": false, "message": "ok"}
	if !reflect.DeepEqual(expectedRes, resBody) {
		t.Errorf("Expected response %v. Got %v", expectedRes, resBody)
	}
}

func TestShouldLoginAndReceiveCookies(t *testing.T) {
	Users = append(Users, UserDto{
		Email:    "qwe",
		Password: "qwe",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/login", toRequestBody(
		map[string]any{"email": "qwe", "password": "qwe"},
	))

	w := httptest.NewRecorder()

	Login(w, request)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d. Got %d", http.StatusOK, w.Code)
	}

	cookies := w.Result().Cookies()

	accessFound := false
	refreshFound := false
	for _, cookie := range cookies {
		if strings.Contains(cookie.Name, JWT_ACCESS_TOKEN_NAME) && cookie.HttpOnly {
			accessFound = true
		}

		if strings.Contains(cookie.Name, JWT_REFRESH_TOKEN_NAME) && cookie.HttpOnly {
			refreshFound = true
		}
	}

	if !accessFound {
		t.Errorf("Expected httpOnly Access Cookie, not found")
	}

	if !refreshFound {
		t.Errorf("Expected httpOnly Refresh Cookie, not found")
	}
}

func TestShouldNotIfIncorrectCredentialsLogin(t *testing.T) {
	Users = append(Users, UserDto{
		Email:    "qwe",
		Password: "qwe",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/login", toRequestBody(
		map[string]any{"email": "qwer", "password": "qwe"},
	))

	w := httptest.NewRecorder()

	Login(w, request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d. Got %d", http.StatusBadRequest, w.Code)
	}

	resBody := make(map[string]any)
	json.NewDecoder(w.Body).Decode(&resBody)
	expectedRes := map[string]any{"error": true, "message": "Invalid email or password"}
	if !reflect.DeepEqual(expectedRes, resBody) {
		t.Errorf("Expected response %v. Got %v", expectedRes, resBody)
	}
}

func TestShouldNotIfNoUsers(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/login", toRequestBody(
		map[string]any{"email": "qwer", "password": "qwe"},
	))

	w := httptest.NewRecorder()

	Login(w, request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d. Got %d", http.StatusBadRequest, w.Code)
	}

	resBody := make(map[string]any)
	json.NewDecoder(w.Body).Decode(&resBody)
	expectedRes := map[string]any{"error": true, "message": "Invalid email or password"}
	if !reflect.DeepEqual(expectedRes, resBody) {
		t.Errorf("Expected response %v. Got %v", expectedRes, resBody)
	}
}

func TestShouldValidateData(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/login", toRequestBody(
		map[string]any{"email": 1, "password": 2},
	))

	w := httptest.NewRecorder()

	Login(w, request)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status code %d. Got %d", http.StatusUnprocessableEntity, w.Code)
	}

	resBody := make(map[string]any)
	json.NewDecoder(w.Body).Decode(&resBody)
	expectedRes := map[string]any{"error": true}
	if !reflect.DeepEqual(expectedRes["error"], resBody["error"]) {
		t.Errorf("Expected response %v. Got %v", expectedRes, resBody)
	}
}

func toRequestBody(body map[string]any) *bytes.Buffer {
	req, err := json.Marshal(body)
	if err != nil {
		log.Panic("cannot marshal json: ", body)
	}

	return bytes.NewBuffer(req)
}
