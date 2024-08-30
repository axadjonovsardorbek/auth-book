package token

import (
	"fmt"
	"log"
	"net/http"
	"time"

	pb "auth/genproto/auth"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/cast"
)

type JWTHandler struct {
	Sub        string
	Exp        string
	Iat        string
	Role       string
	SigningKey string
	Token      string
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

var tokenKey = "my_secret_key"

func GenerateJWTTokenForPhone(user *pb.VerifyPhoneRequest) *Tokens {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["id"] = user.UserId
	accessClaims["phone"] = user.Phone
	accessClaims["role"] = user.Role
	accessClaims["iat"] = time.Now().Unix()
	accessClaims["exp"] = time.Now().Add(1 * time.Hour).Unix() // Expires in 1 hours
	access, err := accessToken.SignedString([]byte(tokenKey))
	if err != nil {
		log.Fatal("Error while generating access token: ", err)
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["id"] = user.UserId
	refreshClaims["phone"] = user.Phone
	refreshClaims["role"] = "user"
	refreshClaims["iat"] = time.Now().Unix()
	refreshClaims["exp"] = time.Now().Add(2 * time.Hour).Unix() // Expires in 2 hours
	refresh, err := refreshToken.SignedString([]byte(tokenKey))
	if err != nil {
		log.Fatal("Error while generating refresh token: ", err)
	}

	return &Tokens{
		AccessToken:  access,
		RefreshToken: refresh,
	}
}

func GenerateJWTToken(user *pb.VerifyEmailRequest) *Tokens {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["id"] = user.UserId
	accessClaims["email"] = user.Email
	accessClaims["role"] = user.Role
	accessClaims["iat"] = time.Now().Unix()
	accessClaims["exp"] = time.Now().Add(1 * time.Hour).Unix() // Expires in 1 hours
	access, err := accessToken.SignedString([]byte(tokenKey))
	if err != nil {
		log.Fatal("Error while generating access token: ", err)
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["id"] = user.UserId
	refreshClaims["email"] = user.Email
	refreshClaims["role"] = "user"
	refreshClaims["iat"] = time.Now().Unix()
	refreshClaims["exp"] = time.Now().Add(2 * time.Hour).Unix() // Expires in 2 hours
	refresh, err := refreshToken.SignedString([]byte(tokenKey))
	if err != nil {
		log.Fatal("Error while generating refresh token: ", err)
	}

	return &Tokens{
		AccessToken:  access,
		RefreshToken: refresh,
	}
}

func ExtractClaim(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		return nil, fmt.Errorf("invalid token or claims")
	}

	return claims, nil
}

func (jwtHandler *JWTHandler) ExtractClaims() (jwt.MapClaims, error) {
	token, err := jwt.Parse(jwtHandler.Token, func(t *jwt.Token) (interface{}, error) {
		return []byte(jwtHandler.SigningKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		return nil, fmt.Errorf("invalid token or claims")
	}

	return claims, nil
}

func GetIdFromToken(ctx *gin.Context) (string, error) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
		return "", nil
	}

	claims, err := ExtractClaim(authHeader)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
		return "", nil
	}

	userId := cast.ToString(claims["id"])
	if userId == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return "", nil
	}

	return userId, nil
}
