package api

import (
	"auth/api/handler"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	files "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Auth service
// @version 1.0
// @description Auth service
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func NewGin(h *handler.Handler) *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	admin := r.Group("/admin")
	{
		admin.POST("/createAdmin/:email", h.CreateAdmin)
		admin.POST("/loginAdmin", h.LoginAdmin)
		admin.POST("/forgetPassword/:email", h.ForgetPassword)
		admin.POST("/resetPassword", h.ResetPassword)
		admin.PUT("/updateAdmin", h.UpdateAdmin)
		admin.PUT("/changePassword", h.ChangePassword)
		admin.DELETE("/deleteAdmin", h.DeleteAdmin)
		admin.GET("/getProfile", h.GetAdminProfile)
		admin.GET("/getAllAdmins", h.GetAllAdmins)
	}

	publisher := r.Group("/publisher")
	{
		publisher.POST("/SignUpPublisher", h.SignUpPublisher) // Workinh
		publisher.POST("/VerifyPublisherEmail", h.VerifyPublisherEmail)
		publisher.POST("/LogInPublisher", h.LogInPublisher)
	}

	auth := r.Group("/auth")
	{
		auth.POST("/enterAccountByPhone/:phone", h.EnterAccountByPhone)
		auth.POST("/verifyPhone", h.VerifyPhone)
		//------------------------------------------------
		auth.POST("/enterAccount/:email", h.EnterAccount)
		auth.POST("/verifyEmail", h.VerifyEmail)
		auth.POST("/refreshToken", h.RefreshToken)
		auth.PUT("/changeEmail", h.ChangeEmail)
		auth.POST("/completeChangeEmail", h.CompleteChangeEmail)
		auth.PUT("/updateUser", h.UpdateUser)
		auth.GET("/getProfile", h.GetProfile)
		auth.GET("/getAllUsers", h.GetAllUsers)
		auth.DELETE("/deleteUser", h.DeleteUser)
		auth.DELETE("/deleteUserByAdmin", h.DeleteUserByAdmin)
	}

	swaggerURL := ginSwagger.URL("http://3.68.216.185:8069/swagger/doc.json")
	r.GET("/swagger/*any", ginSwagger.WrapHandler(files.Handler, swaggerURL))

	return r
}
