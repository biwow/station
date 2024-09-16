package typecache

type ConfigCache struct {
	Addr     string // redis 连接地址
	Password string // redis 密码
	DB       int    // redis 库
	DBPath   string // levelDB 存储位置
}
