// Package storage provides persistent storage for scan results.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ScanRecord is the database model for a completed scan.
type ScanRecord struct {
	gorm.Model
	ScanID       string        `gorm:"uniqueIndex;not null"`
	StartTime    time.Time     `gorm:"not null"`
	EndTime      time.Time     `gorm:"not null"`
	Duration     time.Duration `gorm:"not null"`
	RiskLevel    string        `gorm:"not null"`
	FindingCount int           `gorm:"not null"`
	Hostname     string
	Kernel       string
	ResultsJSON  []byte `gorm:"type:bytea"`
}

// FindingRecord is the database model for a single finding.
type FindingRecord struct {
	gorm.Model
	ScanID      string  `gorm:"index;not null"`
	FindingType string  `gorm:"not null"`
	Risk        string  `gorm:"not null"`
	Title       string
	Description string
	Confidence  float64
	Remediation string
	MITREIDs    string
}

// AlertRecord stores webhook alert delivery history.
type AlertRecord struct {
	gorm.Model
	ScanID      string `gorm:"index"`
	Webhook     string
	Payload     []byte `gorm:"type:bytea"`
	Delivered   bool
	DeliveredAt *time.Time
	ErrorMsg    string
}

// PostgresStore wraps a GORM PostgreSQL connection.
type PostgresStore struct{ db *gorm.DB }

// NewPostgresStore creates a new PostgreSQL store and runs migrations.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting sql.DB: %w", err)
	}
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	if err := db.AutoMigrate(&ScanRecord{}, &FindingRecord{}, &AlertRecord{}); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return &PostgresStore{db: db}, nil
}

// SaveScanResults persists scan results to the database.
func (s *PostgresStore) SaveScanResults(ctx context.Context, results interface{}) error {
	type marshalable interface{ MarshalJSON() ([]byte, error) }
	m, ok := results.(marshalable)
	if !ok {
		return fmt.Errorf("results does not implement MarshalJSON")
	}
	data, err := m.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}
	var parsed struct {
		ScanID    string    `json:"scan_id"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
		Duration  int64     `json:"duration_ns"`
		RiskLevel string    `json:"risk_level"`
		Hostname  string    `json:"hostname"`
		Kernel    string    `json:"kernel"`
		Findings  []struct {
			Type        string  `json:"type"`
			Risk        string  `json:"risk"`
			Title       string  `json:"title"`
			Description string  `json:"description"`
			Confidence  float64 `json:"confidence"`
			Remediation string  `json:"remediation"`
			MITRE       []struct {
				TechniqueID string `json:"technique_id"`
			} `json:"mitre"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("parsing results: %w", err)
	}
	record := &ScanRecord{
		ScanID: parsed.ScanID, StartTime: parsed.StartTime, EndTime: parsed.EndTime,
		Duration: time.Duration(parsed.Duration), RiskLevel: parsed.RiskLevel,
		FindingCount: len(parsed.Findings), Hostname: parsed.Hostname,
		Kernel: parsed.Kernel, ResultsJSON: data,
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return fmt.Errorf("inserting scan record: %w", err)
	}
	for _, f := range parsed.Findings {
		ids := make([]string, 0, len(f.MITRE))
		for _, m := range f.MITRE {
			ids = append(ids, m.TechniqueID)
		}
		fr := &FindingRecord{
			ScanID: parsed.ScanID, FindingType: f.Type, Risk: f.Risk,
			Title: f.Title, Description: f.Description,
			Confidence: f.Confidence, Remediation: f.Remediation,
			MITREIDs: strings.Join(ids, ","),
		}
		if err := s.db.WithContext(ctx).Create(fr).Error; err != nil {
			return fmt.Errorf("inserting finding: %w", err)
		}
	}
	return nil
}

// GetRecentScans returns the most recent n scan records.
func (s *PostgresStore) GetRecentScans(ctx context.Context, n int) ([]*ScanRecord, error) {
	var records []*ScanRecord
	err := s.db.WithContext(ctx).Order("start_time DESC").Limit(n).Find(&records).Error
	return records, err
}

// GetScanByID retrieves a scan record by its ID.
func (s *PostgresStore) GetScanByID(ctx context.Context, scanID string) (*ScanRecord, error) {
	var record ScanRecord
	err := s.db.WithContext(ctx).Where("scan_id = ?", scanID).First(&record).Error
	return &record, err
}

// GetFindingsForScan returns all findings for a scan ID.
func (s *PostgresStore) GetFindingsForScan(ctx context.Context, scanID string) ([]*FindingRecord, error) {
	var findings []*FindingRecord
	err := s.db.WithContext(ctx).Where("scan_id = ?", scanID).Find(&findings).Error
	return findings, err
}

// GetAlertsByRisk returns findings at or above the given risk level.
func (s *PostgresStore) GetAlertsByRisk(ctx context.Context, riskLevel string, limit int) ([]*FindingRecord, error) {
	riskOrder := map[string]int{"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	threshold := riskOrder[riskLevel]
	var all []*FindingRecord
	if err := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit * 4).Find(&all).Error; err != nil {
		return nil, err
	}
	filtered := make([]*FindingRecord, 0, limit)
	for _, f := range all {
		if riskOrder[f.Risk] >= threshold {
			filtered = append(filtered, f)
			if len(filtered) >= limit {
				break
			}
		}
	}
	return filtered, nil
}

// SaveAlert records a webhook alert delivery attempt.
func (s *PostgresStore) SaveAlert(ctx context.Context, alert *AlertRecord) error {
	return s.db.WithContext(ctx).Create(alert).Error
}

// Close closes the database connection pool.
func (s *PostgresStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
