package helper

import (
	"auth/config"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"math/rand"
)

type SmsRequest struct {
	MobilePhone string `json:"mobile_phone"`
	Message     string `json:"message"`
	From        string `json:"from"`
	CallbackURL string `json:"callback_url,omitempty"`
}

func generateVerificationCode() (string, error) {
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(899999) + 100000
	return fmt.Sprintf("%06d", code), nil
}

func SendSms(phone string) (string, error) {
	url := "https://notify.eskiz.uz/api/message/sms/send"
	cfg := config.Load()

	code, err := generateVerificationCode()
	if err != nil {
		return "", fmt.Errorf("error generating Verification code: %v", err)
	}

	token := cfg.SMS_TOKEN
	message := "Kitobol platformasi uchun tasdiqlash kodi - " + code

	smsRequest := SmsRequest{
		MobilePhone: phone,
		Message:     message,
		From:        "4546",
	}

	jsonData, err := json.Marshal(smsRequest)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to send SMS, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	fmt.Println("SMS sent successfully")
	return code, nil
}
