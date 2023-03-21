package data

import (
	"context"
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"sso/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(
	NewData,
	NewDatabase,
	NewRedis,
	NewAuthRepo,
	NewAuthClientStore,
)

// Data .
type Data struct {
	DB    *gorm.DB
	Redis *redis.Client
}

// NewData .
func NewData(logger log.Logger, db *gorm.DB, redis *redis.Client) (*Data, func(), error) {
	cleanup := func() {
		db2, _ := db.DB()
		db2.Close()
		redis.Close()
		log.NewHelper(logger).Info("closing the data resources")
	}
	return &Data{DB: db, Redis: redis}, cleanup, nil
}

// NewDatabase 初始化数据库
func NewDatabase(c *conf.Data) (*gorm.DB, error) {
	// dsn 数据库链接
	dsn := fmt.Sprintf("%s?charset=utf8mb4&parseTime=True&loc=Local", c.GetDatabase().GetSource())

	var dir func(dsn string) gorm.Dialector
	switch c.GetDatabase().GetDriver() {
	case "mysql":
		dir = mysql.Open
	case "postgres":
		dir = postgres.Open
	case "sqlserver":
		dir = sqlserver.Open
	default:
		dir = sqlite.Open
	}

	db, err := gorm.Open(
		dir(dsn),
		&gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDb, err := db.DB()
	if err != nil {
		return nil, err
	}
	// 设置连接池
	// 空闲
	sqlDb.SetMaxIdleConns(50)
	// 打开
	sqlDb.SetMaxOpenConns(100)
	// 超时
	sqlDb.SetConnMaxLifetime(time.Second * 30)

	return db, nil
}

func NewRedis(c *conf.Data) (client *redis.Client, err error) {
	opt, err := redis.ParseURL(fmt.Sprintf("redis://%s", c.GetRedis().GetAddr()))
	if err != nil {
		return
	}
	opt.ReadTimeout = c.GetRedis().GetReadTimeout().AsDuration()
	opt.WriteTimeout = c.GetRedis().GetWriteTimeout().AsDuration()
	opt.PoolSize = 10
	opt.PoolTimeout = 10 * time.Second
	client = redis.NewClient(opt)
	result, err := client.Ping(context.Background()).Result()
	if err != nil || result != "PONG" {
		panic(err)
	}
	return
}
