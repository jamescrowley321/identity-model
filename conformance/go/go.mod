module github.com/jamescrowley321/identity-model/conformance/go

go 1.26.0

require (
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/jamescrowley321/identity-model/go v0.0.0
)

require golang.org/x/sync v0.22.0 // indirect

replace github.com/jamescrowley321/identity-model/go => ../../go
