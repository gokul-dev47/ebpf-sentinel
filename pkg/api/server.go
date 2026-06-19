// Package api implements the REST API server for eBPF Sentinel.
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/detector"
	sentinelmetrics "github.com/gokul-dev47/ebpf-sentinel/pkg/prometheus"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/storage"
	"github.com/sirupsen/logrus"
)

// ServerConfig holds configuration for the REST API server.
type ServerConfig struct {
	Addr    string
	Engine  *detector.Engine
	Store   *storage.PostgresStore
	Metrics *sentinelmetrics.Metrics
	Logger  *logrus.Logger
}

// Server is the REST API server.
type Server struct {
	cfg    ServerConfig
	router *gin.Engine
	log    *logrus.Logger
}

// NewServer creates and configures the REST API server.
func NewServer(cfg ServerConfig) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(loggerMiddleware(cfg.Logger))
	router.Use(securityHeaders())
	s := &Server{cfg: cfg, router: router, log: cfg.Logger}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	v1 := s.router.Group("/api/v1")
	v1.GET("/status", s.handleStatus)
	v1.POST("/scan", s.handleTriggerScan)
	v1.GET("/scan/:id", s.handleGetScan)
	v1.GET("/scans", s.handleListScans)
	v1.GET("/alerts", s.handleListAlerts)
	v1.POST("/alerts/webhook", s.handleConfigureWebhook)
	v1.GET("/metrics", s.handleMetricsSummary)
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().Unix()})
	})
	s.router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
}

// Run starts the HTTP server and blocks until context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:         s.cfg.Addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  90 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleStatus(c *gin.Context) {
	status, err := s.cfg.Engine.GetStatus(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, apiError("getting status", err))
		return
	}
	c.JSON(http.StatusOK, status)
}

func (s *Server) handleTriggerScan(c *gin.Context) {
	var req struct {
		Checks  []string `json:"checks"`
		Timeout int      `json:"timeout_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Checks = []string{"all"}
		req.Timeout = 60
	}
	if len(req.Checks) == 0 {
		req.Checks = []string{"all"}
	}
	if req.Timeout <= 0 {
		req.Timeout = 60
	}
	scanID := fmt.Sprintf("%d", time.Now().UnixNano()%100000000)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
		defer cancel()
		results, err := s.cfg.Engine.Scan(ctx)
		if err != nil {
			s.log.WithError(err).Errorf("async scan %s failed", scanID)
			return
		}
		s.log.Infof("scan %s complete: %d findings", scanID, len(results.Findings))
	}()
	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID, "status": "accepted",
		"message": "Poll /api/v1/scan/" + scanID + " for results.",
	})
}

func (s *Server) handleGetScan(c *gin.Context) {
	scanID := c.Param("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, apiError("missing scan ID", nil))
		return
	}
	if s.cfg.Store == nil {
		c.JSON(http.StatusServiceUnavailable, apiError("storage not configured", nil))
		return
	}
	record, err := s.cfg.Store.GetScanByID(c.Request.Context(), scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, apiError("scan not found", err))
		return
	}
	c.JSON(http.StatusOK, record)
}

func (s *Server) handleListScans(c *gin.Context) {
	if s.cfg.Store == nil {
		c.JSON(http.StatusServiceUnavailable, apiError("storage not configured", nil))
		return
	}
	scans, err := s.cfg.Store.GetRecentScans(c.Request.Context(), 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apiError("querying scans", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"scans": scans, "count": len(scans)})
}

func (s *Server) handleListAlerts(c *gin.Context) {
	if s.cfg.Store == nil {
		c.JSON(http.StatusServiceUnavailable, apiError("storage not configured", nil))
		return
	}
	riskLevel := c.DefaultQuery("risk", "HIGH")
	findings, err := s.cfg.Store.GetAlertsByRisk(c.Request.Context(), riskLevel, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, apiError("querying alerts", err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": findings, "count": len(findings), "risk_floor": riskLevel})
}

func (s *Server) handleConfigureWebhook(c *gin.Context) {
	var req struct {
		URL     string `json:"url" binding:"required"`
		Enabled bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apiError("invalid request", err))
		return
	}
	s.log.Infof("webhook configured: %s (enabled=%v)", req.URL, req.Enabled)
	c.JSON(http.StatusOK, gin.H{"status": "configured", "url": req.URL, "enabled": req.Enabled})
}

func (s *Server) handleMetricsSummary(c *gin.Context) {
	if s.cfg.Metrics == nil {
		c.JSON(http.StatusServiceUnavailable, apiError("metrics not configured", nil))
		return
	}
	c.JSON(http.StatusOK, s.cfg.Metrics.Summary())
}

func loggerMiddleware(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.WithFields(logrus.Fields{
			"method": c.Request.Method, "path": c.Request.URL.Path,
			"status": c.Writer.Status(), "latency": time.Since(start), "ip": c.ClientIP(),
		}).Info("request")
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

func apiError(msg string, err error) gin.H {
	if err != nil {
		return gin.H{"error": msg, "detail": err.Error()}
	}
	return gin.H{"error": msg}
}
