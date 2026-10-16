package mongodb

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/dexidp/dex/storage"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	defaultURI        = "mongodb://127.0.0.1:27017"
	defaultDatabase   = "dex"
	defaultCollection = "storage"
	defaultTimeout    = 5 * time.Second
)

// Config configures the MongoDB storage backend.
type Config struct {
	URI        string `json:"uri"`
	Database   string `json:"database"`
	Collection string `json:"collection"`
}

// Open creates a MongoDB-backed storage implementation.
func (c *Config) Open(logger *slog.Logger) (storage.Storage, error) {
	return c.open(logger)
}

func (c *Config) open(logger *slog.Logger) (*conn, error) {
	uri := c.URI
	if uri == "" {
		uri = defaultURI
	}
	database := c.Database
	if database == "" {
		database = defaultDatabase
	}
	collection := c.Collection
	if collection == "" {
		collection = defaultCollection
	}

	client, err := mongo.Connect(options.Client().
		ApplyURI(uri).
		SetConnectTimeout(defaultTimeout).
		SetServerSelectionTimeout(defaultTimeout))
	if err != nil {
		return nil, fmt.Errorf("connect mongodb: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongodb: %w", err)
	}

	return &conn{
		client:     client,
		collection: client.Database(database).Collection(collection),
		logger:     logger,
	}, nil
}
