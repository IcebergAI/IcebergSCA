module example.com/app

go 1.22

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.9.0
	golang.org/x/text v0.14.0 // indirect
)

// A trailing comment on a replace directive is ordinary: it is where people record
// why the fork exists.
replace github.com/pkg/errors => github.com/example/errors v1.2.3 // patched upstream

replace github.com/stretchr/testify => ./vendor/testify // local checkout
