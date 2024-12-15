# Go TOTP Example

A simple and clean implementation of Time-based One-Time Password (TOTP) using Go and HTML. This package provides both a library for TOTP operations and a working example server.

## Features

- TOTP secret generation
- QR code generation for easy setup with authenticator apps
- TOTP code validation
- Clean, responsive web interface
- Easy to use as a library or standalone example

## Installation

```bash
go get github.com/ivikasavnish/totp
```

## Usage

### As a Library

```go
import "github.com/ivikasavnish/totp/pkg/totp"

// Generate a new TOTP secret
secret, err := totp.GenerateSecret("Example App", "user@example.com")
if err != nil {
    log.Fatal(err)
}

// Validate a TOTP code
isValid := totp.ValidateCode(code, secret)
```

### Running the Example Server

```bash
cd example
go run main.go
```

Then open http://localhost:8080 in your browser.

## License

MIT License - see LICENSE file

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
