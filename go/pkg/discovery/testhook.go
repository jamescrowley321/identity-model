package discovery

import (
	"time"

	"github.com/jamescrowley321/identity-model/go/internal/testhook"
)

func init() {
	testhook.SetDiscoveryClock = func(client any, now func() time.Time) {
		client.(*Client).cache.now = now
	}
}
