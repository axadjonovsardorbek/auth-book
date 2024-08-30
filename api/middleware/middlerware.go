package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	t "auth/api/token"
	"auth/config"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type JwtRoleAuth struct {
	enforcer   *casbin.Enforcer
	jwtHandler t.JWTHandler
}

func NewAuth(enforcer *casbin.Enforcer) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if isPublicRoute(ctx.FullPath()) {
			ctx.Next()
			return
		}

		auth := JwtRoleAuth{
			enforcer: enforcer,
			jwtHandler: t.JWTHandler{
				SigningKey: config.Load().TOKEN_KEY,
			},
		}

		role, err := auth.GetRole(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		allow, err := auth.CheckPermission(ctx, role)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			log.Printf("Authorization error: %v\n", err)
			return
		}

		if !allow {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			return
		}

		ctx.Next()
	}
}

// isPublicRoute checks if the route is public and does not require authentication
func isPublicRoute(path string) bool {
	publicRoutes := []string{
		"/swagger/index.html",
		"/swagger/swagger-ui.css",
		"/swagger/swagger-ui-bundle.js",
		"/swagger/favicon-32x32.png",
		"/swagger/favicon-16x16.png",
		"/swagger/swagger-ui-standalone-preset.js",
		"/swagger/swagger/doc.json",
		"/favicon.ico",
	}

	for _, route := range publicRoutes {
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

func (a *JwtRoleAuth) GetRole(ctx *gin.Context) (string, error) {
	// Retrieve the Authorization header
	jwtToken := ctx.GetHeader("Authorization")

	// Ensure it starts with "Bearer "
	if jwtToken == "" || !strings.HasPrefix(jwtToken, "Bearer ") {
		log.Printf("Invalid or missing Authorization header: %s", jwtToken)
		return "", fmt.Errorf("missing or malformed JWT")
	}

	// Extract the token by removing the "Bearer " prefix
	jwtToken = strings.TrimPrefix(jwtToken, "Bearer ")

	// Set the token for the JWTHandler
	a.jwtHandler.Token = jwtToken

	// Extract claims from the token
	claims, err := a.jwtHandler.ExtractClaims()
	if err != nil {
		log.Println("Error extracting claims:", err)
		return "", err
	}

	// Retrieve and validate the role from claims
	role, ok := claims["role"].(string)
	if !ok {
		log.Printf("Role claim not found or not a string: %v", claims["role"])
		return "", fmt.Errorf("role claim not found or not a string")
	}

	return role, nil
}

// CheckPermission checks if the role has permission to access the route
func (a *JwtRoleAuth) CheckPermission(ctx *gin.Context, role string) (bool, error) {
	method := ctx.Request.Method
	path := ctx.FullPath()

	log.Printf("Checking permissions: role=%s, path=%s, method=%s\n", role, path, method)

	allowed, err := a.enforcer.Enforce(role, path, method)
	if err != nil {
		log.Println("Error checking permission:", err)
		return false, err
	}
	log.Printf("Checking permissions for role=%s, path=%s, method=%s", role, path, method)

	return allowed, nil
}
