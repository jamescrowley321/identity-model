// Command hello is a minimal example that imports an identity-model package
// and compiles, proving the module wiring works end to end.
package main

import (
	"fmt"

	_ "github.com/jamescrowley321/identity-model/go/pkg/discovery"
)

func main() {
	fmt.Println("identity-model/go — scaffolded. See spec/capabilities.md for the roadmap.")
}
