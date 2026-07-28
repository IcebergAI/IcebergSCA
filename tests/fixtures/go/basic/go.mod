module github.com/example/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.17.0
)

require (
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

require github.com/pkg/errors v0.9.1

replace github.com/gin-gonic/gin => github.com/forked/gin v1.9.2

replace github.com/local/thing => ./vendor/thing

exclude github.com/bad/module v1.0.0
