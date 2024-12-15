package totp

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"

	"github.com/pquerna/otp/totp"
)

// GenerateSecret creates a new TOTP secret with QR code
func GenerateSecret(issuer, accountName string) (*TOTPData, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return nil, err
	}

	// Generate QR code
	qrImage, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}

	qrBase64, err := imageToBase64(qrImage)
	if err != nil {
		return nil, err
	}

	return &TOTPData{
		Secret: key.Secret(),
		QRCode: qrBase64,
	}, nil
}

// ValidateCode validates a TOTP code against a secret
func ValidateCode(code, secret string) bool {
	return totp.Validate(code, secret)
}

// TOTPData contains the TOTP secret and QR code
type TOTPData struct {
	Secret string
	QRCode string
}

// imageToBase64 converts an image to base64 string
func imageToBase64(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
