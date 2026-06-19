// Package storage - Redis client for caching and distributed state.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore wraps a Redis client for Sentinel state management.
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore creates a new Redis-backed store.
func NewRedisStore(addr string) (*RedisStore, error) {
	opts, err := redis.ParseURL(addr)
	if err != nil {
		opts = &redis.Options{
			Addr:         addr,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     10,
		}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}
	return &RedisStore{client: client, prefix: "sentinel:"}, nil
}

func (r *RedisStore) key(k string) string { return r.prefix + k }

// CacheLatestScan stores the latest scan result for fast retrieval.
func (r *RedisStore) CacheLatestScan(ctx context.Context, scanID string, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling scan: %w", err)
	}
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.key("latest_scan"), b, 24*time.Hour)
	pipe.Set(ctx, r.key("scan:"+scanID), b, 7*24*time.Hour)
	pipe.LPush(ctx, r.key("scan_history"), scanID)
	pipe.LTrim(ctx, r.key("scan_history"), 0, 99)
	_, err = pipe.Exec(ctx)
	return err
}

// GetLatestScan retrieves the most recent scan from cache.
func (r *RedisStore) GetLatestScan(ctx context.Context) ([]byte, error) {
	data, err := r.client.Get(ctx, r.key("latest_scan")).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("getting latest scan: %w", err)
	}
	return data, nil
}

// PublishAlert publishes a real-time alert to a Redis Pub/Sub channel.
func (r *RedisStore) PublishAlert(ctx context.Context, alert interface{}) error {
	b, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshaling alert: %w", err)
	}
	return r.client.Publish(ctx, r.key("alerts"), b).Err()
}

// SubscribeAlerts returns a subscription to the alerts channel.
func (r *RedisStore) SubscribeAlerts(ctx context.Context) *redis.PubSub {
	return r.client.Subscribe(ctx, r.key("alerts"))
}

// SetProcessBaseline stores a process PID snapshot.
func (r *RedisStore) SetProcessBaseline(ctx context.Context, pids []int) error {
	b, err := json.Marshal(pids)
	if err != nil {
		return fmt.Errorf("marshaling PIDs: %w", err)
	}
	return r.client.Set(ctx, r.key("process_baseline"), b, 6*time.Hour).Err()
}

// GetProcessBaseline retrieves the stored process PID snapshot.
func (r *RedisStore) GetProcessBaseline(ctx context.Context) ([]int, error) {
	data, err := r.client.Get(ctx, r.key("process_baseline")).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("getting baseline: %w", err)
	}
	var pids []int
	return pids, json.Unmarshal(data, &pids)
}

// IncrCounter atomically increments a named counter.
func (r *RedisStore) IncrCounter(ctx context.Context, name string) (int64, error) {
	return r.client.Incr(ctx, r.key("counter:"+name)).Result()
}

// Close closes the Redis connection.
func (r *RedisStore) Close() error { return r.client.Close() }
