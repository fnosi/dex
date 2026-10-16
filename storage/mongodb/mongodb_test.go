package mongodb

import (
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/conformance"
)

var testCollectionCounter atomic.Uint64

func TestMongoDB(t *testing.T) {
	uri := os.Getenv("DEX_MONGODB_URI")
	if uri == "" {
		t.Skip("DEX_MONGODB_URI not set")
	}

	newStorage := func(t *testing.T) storage.Storage {
		logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
		cfg := Config{
			URI:        uri,
			Database:   "dex_storage_test",
			Collection: fmt.Sprintf("conformance_%d_%d", time.Now().UnixNano(), testCollectionCounter.Add(1)),
		}
		c, err := cfg.open(logger)
		if err != nil {
			t.Fatal(err)
		}
		c.dropOnClose = true
		return c
	}

	conformance.RunTests(t, newStorage)
	conformance.RunTransactionTests(t, newStorage)
	conformance.RunConcurrencyTests(t, newStorage)
}
