package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/ivikasavnish/totp/pkg/totp"
)

type PageData struct {
	Secret    string
	QRCode    string
	TOTPCode  string
	IsValid   *bool
	ErrorMsg  string
}

func main() {
	// Load templates
	tmpl := template.Must(template.ParseFiles("templates/index.html"))

	// Generate a new TOTP secret
	totpData, err := totp.GenerateSecret("TOTP Example", "user@example.com")
	if err != nil {
		panic(err)
	}

	// Handler for the main page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := PageData{
			Secret: totpData.Secret,
			QRCode: totpData.QRCode,
		}

		if r.Method == "POST" {
			code := r.FormValue("code")
			valid := totp.ValidateCode(code, totpData.Secret)
			data.IsValid = &valid
			data.TOTPCode = code
		}

		tmpl.Execute(w, data)
	})

	// Start server
	fmt.Println("Server starting on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
