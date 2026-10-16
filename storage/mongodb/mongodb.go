// Package mongodb provides a MongoDB implementation of the Dex storage interface.
package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dexidp/dex/storage"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	clientPrefix         = "client/"
	authCodePrefix       = "auth_code/"
	refreshTokenPrefix   = "refresh_token/"
	authRequestPrefix    = "auth_req/"
	passwordPrefix       = "password/"
	offlineSessionPrefix = "offline_session/"
	connectorPrefix      = "connector/"
	keysName             = "openid-connect-keys"
	deviceRequestPrefix  = "device_req/"
	deviceTokenPrefix    = "device_token/"
	userIdentityPrefix   = "user_identity/"
	authSessionPrefix    = "auth_session/"
)

var _ storage.Storage = (*conn)(nil)

type conn struct {
	client      *mongo.Client
	collection  *mongo.Collection
	logger      *slog.Logger
	dropOnClose bool
}

type document struct {
	ID        string     `bson:"_id"`
	Kind      string     `bson:"kind"`
	Version   int64      `bson:"version"`
	Value     []byte     `bson:"value"`
	ExpiresAt *time.Time `bson:"expiresAt,omitempty"`
}

func (c *conn) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if c.dropOnClose {
		if err := c.collection.Drop(ctx); err != nil {
			_ = c.client.Disconnect(context.Background())
			return err
		}
	}
	return c.client.Disconnect(ctx)
}

func create[T any](ctx context.Context, c *conn, id, kind string, value T, expiresAt *time.Time) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = c.collection.InsertOne(ctx, document{
		ID:        id,
		Kind:      kind,
		Version:   1,
		Value:     payload,
		ExpiresAt: expiresAt,
	})
	if mongo.IsDuplicateKeyError(err) {
		return storage.ErrAlreadyExists
	}
	return err
}

func get[T any](ctx context.Context, c *conn, id string) (T, error) {
	var zero T
	var d document
	if err := c.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&d); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return zero, storage.ErrNotFound
		}
		return zero, err
	}
	var value T
	if err := json.Unmarshal(d.Value, &value); err != nil {
		return zero, err
	}
	return value, nil
}

func list[T any](ctx context.Context, c *conn, kind string) ([]T, error) {
	cursor, err := c.collection.Find(ctx, bson.M{"kind": kind})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var values []T
	for cursor.Next(ctx) {
		var d document
		if err := cursor.Decode(&d); err != nil {
			return nil, err
		}
		var value T
		if err := json.Unmarshal(d.Value, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, cursor.Err()
}

func deleteOne(ctx context.Context, c *conn, id string) error {
	result, err := c.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func updateOne[T any](ctx context.Context, c *conn, id, kind string, updater func(T) (T, error), expires func(T) *time.Time, createIfMissing bool) error {
	var d document
	err := c.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		if !createIfMissing {
			return storage.ErrNotFound
		}
		var zero T
		updated, err := updater(zero)
		if err != nil {
			return err
		}
		if err := create(ctx, c, id, kind, updated, expiryOf(updated, expires)); err != nil {
			if errors.Is(err, storage.ErrAlreadyExists) {
				return fmt.Errorf("concurrent conflicting update for %q", id)
			}
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	var current T
	if err := json.Unmarshal(d.Value, &current); err != nil {
		return err
	}
	updated, err := updater(current)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(updated)
	if err != nil {
		return err
	}
	replacement := document{
		ID:        id,
		Kind:      kind,
		Version:   d.Version + 1,
		Value:     payload,
		ExpiresAt: expiryOf(updated, expires),
	}
	result, err := c.collection.ReplaceOne(ctx, bson.M{"_id": id, "version": d.Version}, replacement)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("concurrent conflicting update for %q", id)
	}
	return nil
}

func updateRefreshWithRetry(ctx context.Context, c *conn, id string, updater func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		var d document
		if err := c.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&d); err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				return storage.ErrNotFound
			}
			return err
		}

		var current storage.RefreshToken
		if err := json.Unmarshal(d.Value, &current); err != nil {
			return err
		}
		updated, err := updater(current)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(updated)
		if err != nil {
			return err
		}

		result, err := c.collection.ReplaceOne(ctx, bson.M{"_id": id, "version": d.Version}, document{
			ID:      id,
			Kind:    refreshTokenPrefix,
			Version: d.Version + 1,
			Value:   payload,
		})
		if err != nil {
			return err
		}
		if result.MatchedCount == 1 {
			return nil
		}
	}
}

func expiryOf[T any](value T, fn func(T) *time.Time) *time.Time {
	if fn == nil {
		return nil
	}
	return fn(value)
}

func timePointer(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func authSessionExpiry(s storage.AuthSession) *time.Time {
	a := s.AbsoluteExpiry
	i := s.IdleExpiry
	switch {
	case a.IsZero():
		return timePointer(i)
	case i.IsZero():
		return timePointer(a)
	case a.Before(i):
		return &a
	default:
		return &i
	}
}

func keyID(prefix, id string) string { return prefix + id }
func keyEmail(prefix, email string) string { return prefix + strings.ToLower(email) }
func keySession(userID, connID string) string {
	return offlineSessionPrefix + strings.ToLower(userID+"|"+connID)
}
func keyUserIdentity(userID, connectorID string) string {
	return userIdentityPrefix + strings.ToLower(userID+"|"+connectorID)
}
func keyAuthSession(id string) string { return authSessionPrefix + id }

func (c *conn) GarbageCollect(ctx context.Context, now time.Time) (result storage.GCResult, err error) {
	deleteExpired := func(kind string) (int64, error) {
		r, err := c.collection.DeleteMany(ctx, bson.M{"kind": kind, "expiresAt": bson.M{"$lt": now}})
		if err != nil {
			return 0, err
		}
		return r.DeletedCount, nil
	}

	if result.AuthRequests, err = deleteExpired(authRequestPrefix); err != nil { return result, err }
	if result.AuthCodes, err = deleteExpired(authCodePrefix); err != nil { return result, err }
	if result.DeviceRequests, err = deleteExpired(deviceRequestPrefix); err != nil { return result, err }
	if result.DeviceTokens, err = deleteExpired(deviceTokenPrefix); err != nil { return result, err }
	if result.AuthSessions, err = deleteExpired(authSessionPrefix); err != nil { return result, err }
	return result, nil
}

func (c *conn) CreateAuthRequest(ctx context.Context, a storage.AuthRequest) error {
	return create(ctx, c, keyID(authRequestPrefix, a.ID), authRequestPrefix, a, timePointer(a.Expiry))
}
func (c *conn) GetAuthRequest(ctx context.Context, id string) (storage.AuthRequest, error) {
	return get[storage.AuthRequest](ctx, c, keyID(authRequestPrefix, id))
}
func (c *conn) UpdateAuthRequest(ctx context.Context, id string, updater func(storage.AuthRequest) (storage.AuthRequest, error)) error {
	return updateOne(ctx, c, keyID(authRequestPrefix, id), authRequestPrefix, updater, func(a storage.AuthRequest) *time.Time { return timePointer(a.Expiry) }, false)
}
func (c *conn) DeleteAuthRequest(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyID(authRequestPrefix, id))
}

func (c *conn) CreateAuthCode(ctx context.Context, a storage.AuthCode) error {
	return create(ctx, c, keyID(authCodePrefix, a.ID), authCodePrefix, a, timePointer(a.Expiry))
}
func (c *conn) GetAuthCode(ctx context.Context, id string) (storage.AuthCode, error) {
	return get[storage.AuthCode](ctx, c, keyID(authCodePrefix, id))
}
func (c *conn) DeleteAuthCode(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyID(authCodePrefix, id))
}

func (c *conn) CreateRefresh(ctx context.Context, r storage.RefreshToken) error {
	return create(ctx, c, keyID(refreshTokenPrefix, r.ID), refreshTokenPrefix, r, nil)
}
func (c *conn) GetRefresh(ctx context.Context, id string) (storage.RefreshToken, error) {
	return get[storage.RefreshToken](ctx, c, keyID(refreshTokenPrefix, id))
}
func (c *conn) UpdateRefreshToken(ctx context.Context, id string, updater func(storage.RefreshToken) (storage.RefreshToken, error)) error {
	return updateRefreshWithRetry(ctx, c, keyID(refreshTokenPrefix, id), updater)
}
func (c *conn) DeleteRefresh(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyID(refreshTokenPrefix, id))
}
func (c *conn) ListRefreshTokens(ctx context.Context) ([]storage.RefreshToken, error) {
	return list[storage.RefreshToken](ctx, c, refreshTokenPrefix)
}

func (c *conn) CreateClient(ctx context.Context, client storage.Client) error {
	return create(ctx, c, keyID(clientPrefix, client.ID), clientPrefix, client, nil)
}
func (c *conn) GetClient(ctx context.Context, id string) (storage.Client, error) {
	return get[storage.Client](ctx, c, keyID(clientPrefix, id))
}
func (c *conn) UpdateClient(ctx context.Context, id string, updater func(storage.Client) (storage.Client, error)) error {
	return updateOne(ctx, c, keyID(clientPrefix, id), clientPrefix, updater, nil, false)
}
func (c *conn) DeleteClient(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyID(clientPrefix, id))
}
func (c *conn) ListClients(ctx context.Context) ([]storage.Client, error) {
	return list[storage.Client](ctx, c, clientPrefix)
}

func (c *conn) CreatePassword(ctx context.Context, p storage.Password) error {
	return create(ctx, c, keyEmail(passwordPrefix, p.Email), passwordPrefix, p, nil)
}
func (c *conn) GetPassword(ctx context.Context, email string) (storage.Password, error) {
	return get[storage.Password](ctx, c, keyEmail(passwordPrefix, email))
}
func (c *conn) UpdatePassword(ctx context.Context, email string, updater func(storage.Password) (storage.Password, error)) error {
	return updateOne(ctx, c, keyEmail(passwordPrefix, email), passwordPrefix, updater, nil, false)
}
func (c *conn) DeletePassword(ctx context.Context, email string) error {
	return deleteOne(ctx, c, keyEmail(passwordPrefix, email))
}
func (c *conn) ListPasswords(ctx context.Context) ([]storage.Password, error) {
	return list[storage.Password](ctx, c, passwordPrefix)
}

func (c *conn) CreateOfflineSessions(ctx context.Context, s storage.OfflineSessions) error {
	return create(ctx, c, keySession(s.UserID, s.ConnID), offlineSessionPrefix, s, nil)
}
func (c *conn) GetOfflineSessions(ctx context.Context, userID, connID string) (storage.OfflineSessions, error) {
	return get[storage.OfflineSessions](ctx, c, keySession(userID, connID))
}
func (c *conn) UpdateOfflineSessions(ctx context.Context, userID, connID string, updater func(storage.OfflineSessions) (storage.OfflineSessions, error)) error {
	return updateOne(ctx, c, keySession(userID, connID), offlineSessionPrefix, updater, nil, false)
}
func (c *conn) DeleteOfflineSessions(ctx context.Context, userID, connID string) error {
	return deleteOne(ctx, c, keySession(userID, connID))
}

func (c *conn) CreateUserIdentity(ctx context.Context, u storage.UserIdentity) error {
	return create(ctx, c, keyUserIdentity(u.UserID, u.ConnectorID), userIdentityPrefix, u, nil)
}
func (c *conn) GetUserIdentity(ctx context.Context, userID, connectorID string) (storage.UserIdentity, error) {
	return get[storage.UserIdentity](ctx, c, keyUserIdentity(userID, connectorID))
}
func (c *conn) UpdateUserIdentity(ctx context.Context, userID, connectorID string, updater func(storage.UserIdentity) (storage.UserIdentity, error)) error {
	return updateOne(ctx, c, keyUserIdentity(userID, connectorID), userIdentityPrefix, updater, nil, false)
}
func (c *conn) DeleteUserIdentity(ctx context.Context, userID, connectorID string) error {
	return deleteOne(ctx, c, keyUserIdentity(userID, connectorID))
}
func (c *conn) ListUserIdentities(ctx context.Context) ([]storage.UserIdentity, error) {
	return list[storage.UserIdentity](ctx, c, userIdentityPrefix)
}

func (c *conn) CreateAuthSession(ctx context.Context, s storage.AuthSession) error {
	return create(ctx, c, keyAuthSession(s.ID), authSessionPrefix, s, authSessionExpiry(s))
}
func (c *conn) GetAuthSession(ctx context.Context, id string) (storage.AuthSession, error) {
	return get[storage.AuthSession](ctx, c, keyAuthSession(id))
}
func (c *conn) UpdateAuthSession(ctx context.Context, id string, updater func(storage.AuthSession) (storage.AuthSession, error)) error {
	return updateOne(ctx, c, keyAuthSession(id), authSessionPrefix, updater, authSessionExpiry, false)
}
func (c *conn) DeleteAuthSession(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyAuthSession(id))
}
func (c *conn) ListAuthSessions(ctx context.Context) ([]storage.AuthSession, error) {
	return list[storage.AuthSession](ctx, c, authSessionPrefix)
}

func (c *conn) CreateConnector(ctx context.Context, connector storage.Connector) error {
	return create(ctx, c, keyID(connectorPrefix, connector.ID), connectorPrefix, connector, nil)
}
func (c *conn) GetConnector(ctx context.Context, id string) (storage.Connector, error) {
	return get[storage.Connector](ctx, c, keyID(connectorPrefix, id))
}
func (c *conn) UpdateConnector(ctx context.Context, id string, updater func(storage.Connector) (storage.Connector, error)) error {
	return updateOne(ctx, c, keyID(connectorPrefix, id), connectorPrefix, updater, nil, false)
}
func (c *conn) DeleteConnector(ctx context.Context, id string) error {
	return deleteOne(ctx, c, keyID(connectorPrefix, id))
}
func (c *conn) ListConnectors(ctx context.Context) ([]storage.Connector, error) {
	return list[storage.Connector](ctx, c, connectorPrefix)
}

func (c *conn) GetKeys(ctx context.Context) (storage.Keys, error) {
	keys, err := get[storage.Keys](ctx, c, keysName)
	if errors.Is(err, storage.ErrNotFound) {
		return storage.Keys{}, nil
	}
	return keys, err
}
func (c *conn) UpdateKeys(ctx context.Context, updater func(storage.Keys) (storage.Keys, error)) error {
	return updateOne(ctx, c, keysName, keysName, updater, nil, true)
}

func (c *conn) CreateDeviceRequest(ctx context.Context, d storage.DeviceRequest) error {
	return create(ctx, c, keyID(deviceRequestPrefix, d.UserCode), deviceRequestPrefix, d, timePointer(d.Expiry))
}
func (c *conn) GetDeviceRequest(ctx context.Context, userCode string) (storage.DeviceRequest, error) {
	return get[storage.DeviceRequest](ctx, c, keyID(deviceRequestPrefix, userCode))
}

func (c *conn) CreateDeviceToken(ctx context.Context, t storage.DeviceToken) error {
	return create(ctx, c, keyID(deviceTokenPrefix, t.DeviceCode), deviceTokenPrefix, t, timePointer(t.Expiry))
}
func (c *conn) GetDeviceToken(ctx context.Context, deviceCode string) (storage.DeviceToken, error) {
	return get[storage.DeviceToken](ctx, c, keyID(deviceTokenPrefix, deviceCode))
}
func (c *conn) UpdateDeviceToken(ctx context.Context, deviceCode string, updater func(storage.DeviceToken) (storage.DeviceToken, error)) error {
	return updateOne(ctx, c, keyID(deviceTokenPrefix, deviceCode), deviceTokenPrefix, updater, func(t storage.DeviceToken) *time.Time { return timePointer(t.Expiry) }, false)
}
