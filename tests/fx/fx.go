package main

import (
	"go.uber.org/fx"
	"log"
)

// Logger 定义一个接口
type Logger interface {
	Log(message string)
}

// ConsoleLogger 实现 Logger 接口的具体类型
type ConsoleLogger struct{}

func (c ConsoleLogger) Log(message string) {
	log.Println(message)
}

func main() {
	// 创建 fx 应用
	app := fx.New(
		// 提供 Logger 类型的实例
		fx.Provide(func() Logger { return ConsoleLogger{} }),
		fx.Invoke(func(l Logger) {
			l.Log("Hello, Fx!")
		}),
	)

	// 运行应用
	app.Run()
}
