package postgres

import (
	"auth/genproto/auth"
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"auth/api/helper"
	t "auth/api/token"

	"golang.org/x/crypto/bcrypt"
)

type AuthStorage struct {
	db *sql.DB
}

func NewAuthStorage(db *sql.DB) *AuthStorage {
	return &AuthStorage{
		db: db,
	}
}

func (s *AuthStorage) EnterAccount(req *auth.EmailRequest) (*auth.InfoResponse, error) {
	return nil, nil
	// This method is never be used
}

func (s *AuthStorage) VerifyEmail(req *auth.VerifyEmailRequest) (*auth.TokenResponse, error) {
	ctx := context.Background()
	query := `INSERT INTO users (id, email, role) VALUES ($1, $2, $3)`

	_, err := s.db.ExecContext(ctx, query, req.UserId, req.Email, req.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user data: %v", err)
	}

	token := t.GenerateJWTToken(req)

	response := &auth.TokenResponse{
		UserId:      req.UserId,
		AccessToken: token.AccessToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}

	return response, nil
}

func (s *AuthStorage) VerifyPhone(req *auth.VerifyPhoneRequest) (*auth.TokenResponse, error) {
	ctx := context.Background()
	query := `INSERT INTO users (id, phone_number, role) VALUES ($1, $2, $3)`

	_, err := s.db.ExecContext(ctx, query, req.UserId, req.Phone, req.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user data: %v", err)
	}

	token := t.GenerateJWTTokenForPhone(req)

	response := &auth.TokenResponse{
		UserId:      req.UserId,
		AccessToken: token.AccessToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}

	return response, nil
}

func (u *AuthStorage) RefreshToken(req *auth.ById) (*auth.TokenResponse, error) {
	ctx := context.Background()
	var user auth.Users
	var role string

	err := u.db.QueryRowContext(ctx, `
	SELECT id, first_name, last_name, email, phone_number, date_of_birth FROM users WHERE id = $1`,
		req.UserId).Scan(&user.UserId, &user.FirstName, &user.LastName, &user.Email, &user.PhoneNumber, &user.DateOfBirth)

	if err != nil {
		if err == sql.ErrNoRows {
			err = u.db.QueryRowContext(ctx, `
			SELECT id, first_name, last_name, email, phone_number, date_of_birth FROM admins WHERE id = $1`,
				req.UserId).Scan(&user.UserId, &user.FirstName, &user.LastName, &user.Email, &user.PhoneNumber, &user.DateOfBirth)

			if err != nil {
				if err == sql.ErrNoRows {
					return nil, fmt.Errorf("user not found")
				}
				return nil, fmt.Errorf("failed to fetch user from admins: %v", err)
			}

			role = "admin"
		} else {
			role = "user"
		}
	} else {
		role = "user"
	}

	request := auth.VerifyEmailRequest{
		UserId: user.UserId,
		Email:  user.Email,
		Role:   role,
	}

	newTokens := t.GenerateJWTToken(&request)

	return &auth.TokenResponse{
		UserId:      user.UserId,
		AccessToken: newTokens.AccessToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}, nil
}

func (s *AuthStorage) ChangeEmail(req *auth.ChangeEmailRequest) (*auth.InfoResponse, error) {
	return &auth.InfoResponse{
		Message: "Email updated successfully, please verify your new email address",
		Success: true,
	}, nil
}

func (s *AuthStorage) CompleteChangeEmail(req *auth.VerifyEmailRequest) (*auth.TokenResponse, error) {
	updateQuery := `UPDATE users SET email = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(context.Background(), updateQuery, req.Email, time.Now().Format(time.RFC3339), req.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to update email: %v", err)
	}

	newToken := t.GenerateJWTToken(req)

	return &auth.TokenResponse{
		UserId:      req.UserId,
		AccessToken: newToken.AccessToken,
		ExpiresAt:   time.Now().Add(time.Hour * 24).Format(time.RFC3339),
	}, nil
}

func (u *AuthStorage) UpdateUser(req *auth.UpdateUserRequest) (*auth.InfoResponse, error) {
	query := `
	INSERT INTO users (id, first_name, last_name, phone_number, date_of_birth)
	VALUES ($1, $2, $3, $4, TO_DATE($5, 'YYYY-MM-DD'))
	ON CONFLICT (id) DO UPDATE SET
		first_name = COALESCE($2, users.first_name),
		last_name = COALESCE($3, users.last_name),
		phone_number = COALESCE($4, users.phone_number),
		date_of_birth = COALESCE(TO_DATE($5, 'YYYY-MM-DD'), users.date_of_birth)
	RETURNING id
	`

	var userId string
	err := u.db.QueryRow(query,
		req.UserId,
		req.FirstName,
		req.LastName,
		req.PhoneNumber,
		req.DateOfBirth,
	).Scan(&userId)

	if err != nil {
		return nil, fmt.Errorf("failed to upsert user: %v", err)
	}

	return &auth.InfoResponse{
		Message: "User upserted successfully",
		Success: true,
	}, nil
}

func (u *AuthStorage) GetProfile(req *auth.ById) (*auth.Users, error) {
	query := ` 
	SELECT first_name, last_name, email, date_of_birth, phone_number
	FROM users
	WHERE id = $1
	`

	row := u.db.QueryRow(query, req.UserId)

	resp := &auth.Users{}

	err := row.Scan(
		&resp.FirstName,
		&resp.LastName,
		&resp.Email,
		&resp.DateOfBirth,
		&resp.PhoneNumber,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error fetching profile: %w", err)
	}

	return resp, nil
}

func (u *AuthStorage) GetAllUsers(req *auth.ById) (*auth.GetAllUsersResponse, error) {
	var role string
	err := u.db.QueryRow("SELECT role FROM users WHERE id = $1", req.UserId).Scan(&role)
	if err != nil {
		return nil, fmt.Errorf("failed to get user role: %v", err)
	}

	if role != "admin" && role != "super_admin" {
		return nil, fmt.Errorf("user is not authorized to view all users")
	}

	rows, err := u.db.Query("SELECT first_name, last_name, phone_number, date_of_birth FROM users WHERE deleted_at = 0")
	if err != nil {
		return nil, fmt.Errorf("failed to get all users: %v", err)
	}
	defer rows.Close()

	response := &auth.GetAllUsersResponse{}

	for rows.Next() {
		var user auth.Users
		err := rows.Scan(&user.FirstName, &user.LastName, &user.PhoneNumber, &user.DateOfBirth)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %v", err)
		}
		response.Users = append(response.Users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %v", err)
	}

	return response, nil
}

func (u *AuthStorage) DeleteUser(req *auth.ById) (*auth.InfoResponse, error) {
	_, err := u.db.Exec("UPDATE users SET deleted_at = $1 WHERE id = $2", time.Now().Unix(), req.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete user: %v", err)
	}

	return &auth.InfoResponse{
		Message: "User successfully deleted.",
		Success: true,
	}, nil
}

func (u *AuthStorage) DeleteUserByAdmin(req *auth.ByAdmin) (*auth.InfoResponse, error) {
	var role string
	err := u.db.QueryRow("SELECT role FROM users WHERE id = $1", req.AdminId).Scan(&role)
	if err != nil {
		return nil, fmt.Errorf("failed to verify admin status: %v", err)
	}

	if role != "admin" && role != "super_admin" {
		return nil, fmt.Errorf("unauthorized: user is not an admin or superadmin")
	}

	_, err = u.db.Exec("UPDATE users SET deleted_at = $1 WHERE id = $2", time.Now().Unix(), req.UserId)
	if err != nil {
		return nil, fmt.Errorf("failed to delete user: %v", err)
	}

	return &auth.InfoResponse{
		Message: "User successfully deleted.",
		Success: true,
	}, nil
}

func (u *AuthStorage) CreateAdmin(req *auth.EmailRequest) (*auth.LogInAdminRequest, error) {
	ctx := context.Background()

	var role string
	checkQuery := `SELECT role FROM admins WHERE id = $1`
	err := u.db.QueryRowContext(ctx, checkQuery, req.SuperAdminId).Scan(&role)
	if err != nil {
		log.Printf("Failed to verify super admin: %v", err)
		return nil, fmt.Errorf("failed to verify super admin")
	}

	if role != "super_admin" {
		log.Printf("Provided SuperAdminId does not have super admin privileges")
		return nil, fmt.Errorf("invalid super admin privileges")
	}

	password, err := helper.GeneratePassword(8)
	if err != nil {
		log.Printf("Error generating new password: %v", err)
		return nil, fmt.Errorf("unable to generate password")
	}

	hashedPassword, err := helper.HashPassword(password)
	if err != nil {
		log.Printf("Error hashing the password: %v", err)
		return nil, fmt.Errorf("unable to hash password")
	}

	query := `INSERT INTO admins (id, email, role, password) VALUES ($1, $2, $3, $4)`
	_, err = u.db.ExecContext(ctx, query, req.AdminId, req.Email, req.Role, hashedPassword)
	if err != nil {
		log.Printf("Failed to insert user data: %v", err)
		return nil, fmt.Errorf("failed to create admin")
	}

	response := &auth.LogInAdminRequest{
		Email:    req.Email,
		Password: password,
	}

	return response, nil
}

func (u *AuthStorage) LogInAdmin(req *auth.LogInAdminRequest) (*auth.TokenResponse, error) {
	ctx := context.Background()

	var (
		hashedPassword string
		userID         string
	)

	query := `SELECT id, password FROM admins WHERE email = $1`
	err := u.db.QueryRowContext(ctx, query, req.Email).Scan(&userID, &hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin not found")
		}
		return nil, fmt.Errorf("error retrieving admin information: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %v", err)
	}

	tokenReq := auth.VerifyEmailRequest{
		UserId: userID,
		Email:  req.Email,
		Role:   "admin",
	}

	token := t.GenerateJWTToken(&tokenReq)

	response := &auth.TokenResponse{
		UserId:      userID,
		AccessToken: token.AccessToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}

	return response, nil
}

func (u *AuthStorage) UpdateAdmin(req *auth.UpdateUserRequest) (*auth.InfoResponse, error) {
	query := `
    INSERT INTO admins (id, first_name, last_name, phone_number, date_of_birth)
    VALUES ($1, $2, $3, $4, TO_DATE($5, 'YYYY-MM-DD'))
    ON CONFLICT (id) DO UPDATE SET
        first_name = COALESCE($2, admins.first_name),
        last_name = COALESCE($3, admins.last_name),
        phone_number = COALESCE($4, admins.phone_number),
        date_of_birth = COALESCE(TO_DATE($5, 'YYYY-MM-DD'), admins.date_of_birth)
    RETURNING id
    `

	var userId string
	err := u.db.QueryRow(query,
		req.UserId,      // $1
		req.FirstName,   // $2
		req.LastName,    // $3
		req.PhoneNumber, // $4
		req.DateOfBirth, // $5
	).Scan(&userId)

	if err != nil {
		// Log the error for debugging purposes
		log.Printf("Error upserting admin: %v", err)
		return nil, fmt.Errorf("failed to upsert user: %v", err)
	}

	return &auth.InfoResponse{
		Message: "User upserted successfully",
		Success: true,
	}, nil
}

func (u *AuthStorage) ChangePassword(req *auth.ChangePasswordRequest) (*auth.InfoResponse, error) {
	var currentPasswordHash string
	query := `
		SELECT password
		FROM admins
		WHERE id = $1 AND deleted_at = 0
	`
	err := u.db.QueryRow(query, req.UserId).Scan(&currentPasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return &auth.InfoResponse{Success: false, Message: "Admin not found or already deleted"}, nil
		}
		return nil, fmt.Errorf("could not fetch user: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(req.OldPassword))
	if err != nil {
		return &auth.InfoResponse{Success: false, Message: "Current password is incorrect"}, nil
	}

	hashedNewPassword, err := helper.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("could not hash new password: %v", err)
	}

	updateQuery := `
		UPDATE admins
		SET password = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2 AND deleted_at = 0
	`

	result, err := u.db.Exec(updateQuery, hashedNewPassword, req.UserId)
	if err != nil {
		return &auth.InfoResponse{Success: false, Message: "Failed to update password"}, fmt.Errorf("could not change password: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &auth.InfoResponse{Success: false, Message: "Failed to update password"}, fmt.Errorf("could not determine rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return &auth.InfoResponse{Success: false, Message: "Failed to update password"}, fmt.Errorf("no rows were updated")
	}

	return &auth.InfoResponse{Success: true, Message: "Password successfully changed"}, nil
}

func (s *AuthStorage) ResetPassword(req *auth.ResetPasswordRequest) (*auth.InfoResponse, error) {
	hashedNewPassword, err := helper.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("could not hash new password: %v", err)
	}

	updateQuery := `
		UPDATE admins
		SET password = $1, updated_at = CURRENT_TIMESTAMP
		WHERE email = $2 AND deleted_at = 0
		`
	result, err := s.db.Exec(updateQuery, hashedNewPassword, req.Email)
	if err != nil {
		return &auth.InfoResponse{Success: false, Message: "Failed to reset password"}, fmt.Errorf("could not reset password: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return &auth.InfoResponse{Success: false, Message: "Failed to reset password"}, fmt.Errorf("could not determine rows affected: %v", err)
	}
	if rowsAffected == 0 {
		return &auth.InfoResponse{Success: false, Message: "Failed to reset password"}, fmt.Errorf("no rows were updated")
	}

	return &auth.InfoResponse{Success: true, Message: "Password successfully reset"}, nil
}

func (u *AuthStorage) GetAdmin(req *auth.ById) (*auth.Users, error) {
	query := ` 
	SELECT first_name, last_name, email, date_of_birth, phone_number
	FROM admins
	WHERE id = $1
	`

	row := u.db.QueryRow(query, req.UserId)

	resp := &auth.Users{}

	err := row.Scan(
		&resp.FirstName,
		&resp.LastName,
		&resp.Email,
		&resp.DateOfBirth,
		&resp.PhoneNumber,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error fetching profile: %w", err)
	}

	return resp, nil
}

func (u *AuthStorage) GetAllAdmins(req *auth.ById) (*auth.GetAllUsersResponse, error) {
	ctx := context.Background()

	var role string
	roleQuery := `SELECT role FROM admins WHERE id = $1`
	err := u.db.QueryRowContext(ctx, roleQuery, req.UserId).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user information: %v", err)
	}

	if role != "super_admin" {
		return nil, fmt.Errorf("access denied: only superadmins can view all admins")
	}

	query := `SELECT id, first_name, last_name, email, phone_number, date_of_birth FROM admins`
	rows, err := u.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error retrieving admins: %v", err)
	}
	defer rows.Close()

	var admins []*auth.Users
	for rows.Next() {
		var admin auth.Users
		if err := rows.Scan(&admin.UserId, &admin.FirstName, &admin.LastName, &admin.Email, &admin.PhoneNumber, &admin.DateOfBirth); err != nil {
			return nil, fmt.Errorf("error scanning admin row: %v", err)
		}
		admins = append(admins, &admin)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over admin rows: %v", err)
	}

	response := &auth.GetAllUsersResponse{
		Users: admins,
	}

	return response, nil
}

func (u *AuthStorage) DeleteAdmin(req *auth.BySuperAdmin) (*auth.InfoResponse, error) {
	var requesterRole string
	err := u.db.QueryRow("SELECT role FROM admins WHERE id = $1", req.SuperAdminId).Scan(&requesterRole)
	if err != nil {
		return &auth.InfoResponse{}, fmt.Errorf("failed to verify superadmin status: %v", err)
	}

	if requesterRole != "super_admin" {
		return &auth.InfoResponse{}, fmt.Errorf("unauthorized: user is not a superadmin")
	}

	var adminRole string
	err = u.db.QueryRow("SELECT role FROM admins WHERE id = $1", req.AdminId).Scan(&adminRole)
	if err != nil {
		return &auth.InfoResponse{}, fmt.Errorf("failed to verify admin existence: %v", err)
	}

	if adminRole != "admin" {
		return &auth.InfoResponse{}, fmt.Errorf("admin does not exist or is not of role 'admin'")
	}

	_, err = u.db.Exec("UPDATE admins SET deleted_at = $1 WHERE id = $2", time.Now().Unix(), req.AdminId)
	if err != nil {
		return &auth.InfoResponse{}, fmt.Errorf("failed to delete admin: %v", err)
	}

	return &auth.InfoResponse{
		Message: "Admin successfully deleted.",
		Success: true,
	}, nil
}

func (u *AuthStorage) VerifyPublisherEmail(req *auth.VerifyPublisherEmailRequest) (*auth.TokenResponse, error) {
	query := `INSERT INTO publishers (id, name, email, password, phone_number, username, img_url, role) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := u.db.Exec(query, req.PublisherId, req.Name, req.Email, req.Password, req.PhoneNumber, req.Username, req.ImgUrl, req.Role)
	if err != nil {
		return nil, err
	}

	req_tkn := auth.VerifyEmailRequest{
		UserId: req.PublisherId,
		Email:  req.Email,
		Role:   "publisher",
	}

	tkn := t.GenerateJWTToken(&req_tkn)

	return &auth.TokenResponse{UserId: req.PublisherId, AccessToken: tkn.AccessToken, ExpiresAt: time.Now().Add(1 * time.Hour).Format(time.RFC3339)}, nil
}

func (u *AuthStorage) LogInPublisher(req *auth.LoginPublisherRequest) (*auth.TokenResponse, error) {
	var publisherId, hashedPassword, email string
	fmt.Println("--------------------------->", req.Password)
	fmt.Println("--------------------------->", req.Username)

	query := `SELECT id, password, email FROM publishers WHERE username = $1 OR email = $1`
	err := u.db.QueryRow(query, req.Username).Scan(&publisherId, &hashedPassword, &email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid username or email")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	reqTkn := auth.VerifyEmailRequest{
		UserId: publisherId,
		Email:  email,
		Role:   "publisher",
	}

	tkn := t.GenerateJWTToken(&reqTkn)

	return &auth.TokenResponse{
		UserId:      publisherId,
		AccessToken: tkn.AccessToken,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}, nil
}
