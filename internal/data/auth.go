package data

import (
	"context"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"golang.org/x/crypto/bcrypt"

	"gorm.io/gorm"

	"sso/internal/biz"
)

type authRepo struct {
	data *Data
}

func NewAuthRepo(data *Data) biz.AuthRepo {
	return &authRepo{data: data}
}

// Auth 账号密码 权限验证
func (j *authRepo) Auth(ctx context.Context, user *biz.User, clientID, username, password string) error {
	err := j.data.DB.Where("username = ? and status = ?", username, 0).First(user).Error
	if err != nil {
		return err
	}
	//hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	//if err != nil {
	//	return nil, err
	//}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		user = nil
		return err
	}
	return nil
}

func NewAuthClientStore(db *gorm.DB) oauth2.ClientStore {
	return &AuthClientStore{db: db}
}

type AuthClientStore struct {
	models.Client
	db *gorm.DB
}

func (a *AuthClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	if id == "" {
		return nil, nil
	}
	var tenant biz.Tenant
	err := a.db.WithContext(ctx).Limit(1).Find(&tenant, "id = ?", id).Error

	if err != nil {
		return nil, err
	}
	return &models.Client{ID: string(tenant.ID), Secret: tenant.Secret, Domain: tenant.Domain, UserID: tenant.UserID}, err
}
func (a *AuthClientStore) VerifyPassword(secret string) bool {
	return a.Secret == secret
}
