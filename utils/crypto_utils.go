package utils

import (
	"github.com/alexedwards/argon2id"
)

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
func CreateHash(password string) (string, error) {
	params := &argon2id.Params{
		Memory:      19 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func CompareHashAndPassword(hashedPassword, password string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, hashedPassword)
	if err != nil {
		return false, err
	}
	return match, nil
}

// func CreateHash(password string) (string, error) {
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(hashedPassword), nil
// }

// func CompareHashAndPassword(hashedPassword, password string) (bool, error) {
// 	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
// 	if err != nil {
// 		return false, err
// 	}
// 	return true, nil
// }
