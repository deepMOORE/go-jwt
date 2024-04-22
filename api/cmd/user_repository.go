package main

import "errors"

func GetUserByEmailAndPassword(email string, password string) (UserDto, error) {
	for _, user := range Users {
		if user.Email == email && user.Password == password {
			return user, nil
		}
	}

	return UserDto{}, errors.New("user not found")
}

func GetUserById(userId int) (UserDto, error) {
	for _, user := range Users {
		if user.Id == userId {
			return user, nil
		}
	}

	return UserDto{}, errors.New("user not found")
}
