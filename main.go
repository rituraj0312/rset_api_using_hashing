package main

import (
	"database/sql"
	"encoding/json"

	//  "errors"
	"fmt"
	"log"
	"net/http"

	
	"github.com/go-mysql/errors"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var user_db *sql.DB
var err error


type User struct {
	Username string `json:"u_name"`
	Password string `json:"psswd"`
}
type User2 struct {
	Username  string `json:"u_name"`
	Password2 string `json:"psswd"`
}

var user User
var user2 User2

func hashAndSalt(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}
func comparePasswords(hashedPwd string, plainPwd []byte) bool {

	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func sign_up(w http.ResponseWriter, r *http.Request) {

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Println("Failed to parse input data", err)
		return
	}

	
	pwd := []byte(user.Password)
	hash := hashAndSalt(pwd)
	user.Password = hash

	query1 := "INSERT INTO  users (Username,Password) VALUES (?,?)"
	_, err1 := user_db.Query(query1, user.Username, user.Password)

	

	if err1 != nil {
		
		errorcode := errors.MySQLErrorCode(err1)
		if errorcode==1062{
			fmt.Println("username already present,change it and try again ",err1.Error())
		}
		return

	} else {
		fmt.Println("data successfully inserted into the database")
		json.NewEncoder(w).Encode("sign up : successful")
	}

}

func log_in(w http.ResponseWriter, r *http.Request) {

	json.NewDecoder(r.Body).Decode(&user2)

	var bal2 User2
	bal, e := user_db.Query("select username, password from users where username=?", user2.Username)

	if e != nil {
		fmt.Println("error in selecting username from database ", e)
		return
	}
	for bal.Next() {
		scan_errr := bal.Scan(&bal2.Username, &bal2.Password2)
		if scan_errr != nil {
			fmt.Println("error in scan", scan_errr)
		}

	}

	z := []byte(user2.Password2)

	m := comparePasswords(bal2.Password2, z)

	if user2.Username == bal2.Username && m {
		json.NewEncoder(w).Encode("successsful log in ")
	} else {
		if user2.Username != bal2.Username {
			json.NewEncoder(w).Encode("invalid username")
		} else {
			json.NewEncoder(w).Encode("invalid password")
		}

	}
}

func main() {
	user_db, err = sql.Open("mysql", "root:RsR@0310@tcp(localhost:3306)/user_db")
	if err != nil {
		fmt.Println("Failed to connect to database")
		return
	} else {
		fmt.Println("connection established")
	}
	defer user_db.Close()
	http.HandleFunc("/sign_up", sign_up)
	http.HandleFunc("/log_in", log_in)

	http.ListenAndServe(":8000", nil)

}
