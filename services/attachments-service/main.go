package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"

	"github.com/LBaronceli/doxly-backend/shared/auth"
	"github.com/LBaronceli/doxly-backend/shared/db"
	"github.com/LBaronceli/doxly-backend/shared/httpx"
	"github.com/LBaronceli/doxly-backend/shared/telemetry"
)

/* ========= types & helpers ========= */

type Server struct {
	log        *zap.SugaredLogger
	dbx        *sqlx.DB
	pub        ed25519.PublicKey

	// Internal MinIO/S3 client for server-side ops (StatObject, GetObject, etc.)
	minio *minio.Client

	// Presign client that targets the exact hostname clients will call
	presign    *minio.Client
	bucket     string
	prefix     string
	presignTTL time.Duration
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type ctxClaimsKey struct{}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, publicMsg string, err error, fields ...any) {
	rid := middleware.GetReqID(r.Context())
	fs := append([]any{"rid", rid}, fields...)
	if err != nil {
		s.log.With(fs...).Errorf("%s: %v", publicMsg, err)
	} else {
		s.log.With(fs...).Errorf("%s", publicMsg)
	}
	httpJSON(w, status, map[string]string{"error": publicMsg})
}

func httpJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

/* ========= main ========= */

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	port := envOr("PORT", "8080")

	// DB
	sqlxDB := db.MustOpen(context.Background(), "DATABASE_URL")
	defer sqlxDB.Close()

	// Verify key (prefer JWKS)
	var pub ed25519.PublicKey
	if jwksURL := os.Getenv("AUTH_JWKS_URL"); jwksURL != "" {
		for i := 0; i < 20; i++ {
			p, _, err := auth.FetchEd25519FromJWKS(jwksURL)
			if err == nil {
				pub = p
				log.Infof("attachments: using JWKS verifier: %s", jwksURL)
				break
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if pub == nil {
			log.Fatalf("jwks fetch failed after retries")
		}
	} else {
		signer, err := auth.LoadEd25519FromEnv()
		if err != nil {
			log.Fatalf("jwt keys: %v", err)
		}
		pub = signer.Public()
		log.Infof("attachments: using env public key (fallback)")
	}

	// MinIO / S3 config
	endpoint := envOr("MINIO_ENDPOINT", "minio:9000") // inside docker network
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	useSSL := strings.EqualFold(envOr("MINIO_USE_SSL", "false"), "true")
	region := envOr("MINIO_REGION", "us-east-1") // avoids GetBucketLocation during presign

	// Internal client (server-side ops)
	internalMC, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       useSSL,
		Region:       region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		log.Fatalf("minio client: %v", err)
	}

	// Presign client: must use the EXACT host clients will call (SigV4 includes host)
	var presignMC *minio.Client
	if pubBase := os.Getenv("MINIO_PUBLIC_BASE"); pubBase != "" {
		u, err := url.Parse(pubBase) // e.g., http://localhost:9000 or https://files.example.com
		if err != nil {
			log.Fatalf("MINIO_PUBLIC_BASE parse error: %v", err)
		}
		presignMC, err = minio.New(u.Host, &minio.Options{
			Creds:        credentials.NewStaticV4(accessKey, secretKey, ""),
			Secure:       u.Scheme == "https",
			Region:       region,
			BucketLookup: minio.BucketLookupPath,
		})
		if err != nil {
			log.Fatalf("presign client: %v", err)
		}
		log.Infof("attachments: presigning against %s (region=%s)", pubBase, region)
	} else {
		// Fallback: only safe if clients also call the same host
		log.Infof("attachments: MINIO_PUBLIC_BASE not set; presigning with internal endpoint %s (region=%s)", endpoint, region)
		presignMC = internalMC
	}

	bucket := envOr("MINIO_BUCKET", "doxly")
	prefix := strings.Trim(envOr("MINIO_PREFIX", "uploads"), "/")
	ttl := 10 * time.Minute

	s := &Server{
		log:        log,
		dbx:        sqlxDB,
		pub:        pub,
		minio:      internalMC,
		presign:    presignMC,
		bucket:     bucket,
		prefix:     prefix,
		presignTTL: ttl,
	}

	// Router
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP)
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := sqlxDB.DB.PingContext(ctx); err != nil {
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(pr chi.Router) {
			pr.Use(s.jwtVerifierMiddleware())

			// Upload flow
			pr.Post("/customers/{id}/attachments/presign", s.handlePresign)
			pr.Post("/customers/{id}/attachments/confirm", s.handleConfirm)
			pr.Get("/customers/{id}/attachments", s.handleList)

			// Download URL (presigned GET)
			pr.Get("/customers/{id}/attachments/{attachment_id}/download-url", s.handleDownloadURL)

			// OPTIONAL: proxy/stream download via API (comment in if desired)
			// pr.Get("/customers/{id}/attachments/{attachment_id}/download", s.handleDownloadStream)
		})
	})

	h := httpx.Common(r)
	s.log.Infof("attachments-service listening on :%s", port)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      h,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.log.Fatalf("server: %v", err)
	}
}

/* ========= auth middleware ========= */

func (s *Server) jwtVerifierMiddleware() func(http.Handler) http.Handler {
	public := s.pub
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ah := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
				return
			}
			tokenStr := strings.TrimSpace(ah[len("Bearer "):])

			claims := jwt.MapClaims{}
			tok, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
				if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
					return nil, jwt.ErrTokenUnverifiable
				}
				return public, nil
			})
			if err != nil || !tok.Valid {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
			if aud, _ := claims["aud"].(string); aud != "doxly" {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad audience"})
				return
			}
			if iss, _ := claims["iss"].(string); iss != "doxly-auth" {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad issuer"})
				return
			}
			ctx := context.WithValue(r.Context(), ctxClaimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getClaims(r *http.Request) jwt.MapClaims {
	if v := r.Context().Value(ctxClaimsKey{}); v != nil {
		if c, ok := v.(jwt.MapClaims); ok {
			return c
		}
	}
	return jwt.MapClaims{}
}

func orgFromJWT(r *http.Request) (string, bool) {
	claims := getClaims(r)
	orgID, _ := claims["org_id"].(string)
	return orgID, orgID != ""
}

func userFromJWT(r *http.Request) (string, bool) {
	claims := getClaims(r)
	sub, _ := claims["sub"].(string)
	return sub, sub != ""
}

/* ========= store ========= */

type Attachment struct {
	ID          string    `db:"id" json:"id"`
	OrgID       string    `db:"org_id" json:"org_id"`
	CustomerID  string    `db:"customer_id" json:"customer_id"`
	ObjectKey   string    `db:"object_key" json:"object_key"`
	Filename    string    `db:"filename" json:"filename"`
	ContentType *string   `db:"content_type" json:"content_type,omitempty"`
	SizeBytes   *int64    `db:"size_bytes" json:"size_bytes,omitempty"`
	ETag        *string   `db:"etag" json:"etag,omitempty"`
	UploadedBy  string    `db:"uploaded_by" json:"uploaded_by"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

func (s *Server) assertCustomerInOrg(ctx context.Context, customerID, orgID string) error {
	var ok bool
	err := s.dbx.QueryRowContext(ctx,
		`select true from customers where id=$1 and org_id=$2`,
		customerID, orgID,
	).Scan(&ok)
	if err == sql.ErrNoRows {
		return fmt.Errorf("customer not in org")
	}
	return err
}

func (s *Server) insertAttachment(ctx context.Context, a Attachment) (Attachment, error) {
	var out Attachment
	err := s.dbx.QueryRowxContext(ctx, `
		insert into attachments (org_id, customer_id, object_key, filename, content_type, size_bytes, etag, uploaded_by)
		values ($1,$2,$3,$4,$5,$6,$7,$8)
		returning id, org_id, customer_id, object_key, filename, content_type, size_bytes, etag, uploaded_by, created_at
	`, a.OrgID, a.CustomerID, a.ObjectKey, a.Filename, a.ContentType, a.SizeBytes, a.ETag, a.UploadedBy).StructScan(&out)
	return out, err
}

func (s *Server) listAttachments(ctx context.Context, customerID string, limit, offset int) ([]Attachment, error) {
	var out []Attachment
	err := s.dbx.SelectContext(ctx, &out, `
		select id, org_id, customer_id, object_key, filename, content_type, size_bytes, etag, uploaded_by, created_at
		from attachments
		where customer_id=$1
		order by created_at desc
		limit $2 offset $3
	`, customerID, limit, offset)
	return out, err
}

func (s *Server) getAttachment(ctx context.Context, attachmentID string) (Attachment, error) {
	var a Attachment
	err := s.dbx.GetContext(ctx, &a, `
		select id, org_id, customer_id, object_key, filename, content_type, size_bytes, etag, uploaded_by, created_at
		from attachments
		where id=$1
	`, attachmentID)
	return a, err
}

/* ========= handlers ========= */

type presignReq struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
}

type presignResp struct {
	URL       string `json:"url"`
	ObjectKey string `json:"object_key"`
	ExpiresIn int64  `json:"expires_in_seconds"`
}

func (s *Server) handlePresign(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := chi.URLParam(r, "id")

	var in presignReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Filename) == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json/filename"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.assertCustomerInOrg(ctx, customerID, orgID); err != nil {
		s.fail(w, r, http.StatusForbidden, "customer not in org", err, "customer_id", customerID, "org_id", orgID)
		return
	}

	// path: uploads/<org>/<customer>/YYYY/MM/<filename>
	safeName := path.Base(strings.ReplaceAll(in.Filename, "..", ""))
	dateSeg := time.Now().UTC().Format("2006/01")
	objectKey := path.Join(s.prefix, orgID, customerID, dateSeg, safeName)

	// Presign against the real external host (SigV4 includes host in signature)
	signedURL, err := s.presign.PresignedPutObject(ctx, s.bucket, objectKey, s.presignTTL)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "presign failed", err, "object_key", objectKey)
		return
	}

	httpJSON(w, http.StatusOK, presignResp{
		URL:       signedURL.String(),
		ObjectKey: objectKey,
		ExpiresIn: int64(s.presignTTL.Seconds()),
	})
}

type confirmReq struct {
	ObjectKey   string  `json:"object_key"`
	Filename    string  `json:"filename"`
	ContentType *string `json:"content_type"`
	Size        *int64  `json:"size"`
	ETag        *string `json:"etag"` // optional override; otherwise we use object ETag from MinIO
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	uploader, ok := userFromJWT(r) // JWT sub (uuid)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := chi.URLParam(r, "id")

	var in confirmReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.ObjectKey) == "" || strings.TrimSpace(in.Filename) == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json/object_key/filename"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.assertCustomerInOrg(ctx, customerID, orgID); err != nil {
		s.fail(w, r, http.StatusForbidden, "customer not in org", err, "customer_id", customerID, "org_id", orgID)
		return
	}

	// Validate object in MinIO (internal endpoint)
	st, err := s.minio.StatObject(ctx, s.bucket, in.ObjectKey, minio.StatObjectOptions{})
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "object not found", err, "object_key", in.ObjectKey)
		return
	}
	size := st.Size
	objETag := strings.Trim(st.ETag, "\"")
	if in.Size != nil && *in.Size != size {
		s.fail(w, r, http.StatusBadRequest, "size mismatch", fmt.Errorf("got=%d want=%d", size, *in.Size), "object_key", in.ObjectKey)
		return
	}
	etag := &objETag
	if in.ETag != nil && *in.ETag != "" {
		etag = in.ETag
	}

	a, err := s.insertAttachment(ctx, Attachment{
		OrgID:       orgID,
		CustomerID:  customerID,
		ObjectKey:   in.ObjectKey,
		Filename:    in.Filename,
		ContentType: in.ContentType,
		SizeBytes:   &size,
		ETag:        etag,     // store ETag
		UploadedBy:  uploader, // from JWT sub
	})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "confirm failed (db)", err, "object_key", in.ObjectKey)
		return
	}
	httpJSON(w, http.StatusCreated, a)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.assertCustomerInOrg(ctx, customerID, orgID); err != nil {
		s.fail(w, r, http.StatusForbidden, "customer not in org", err, "customer_id", customerID, "org_id", orgID)
		return
	}

	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}

	items, err := s.listAttachments(ctx, customerID, limit, offset)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "list failed", err, "customer_id", customerID)
		return
	}
	httpJSON(w, http.StatusOK, map[string]any{
		"items":  items,
		"limit":  limit,
		"offset": offset,
	})
}

/* ========= download handlers ========= */

type downloadURLResp struct {
	URL string `json:"url"`
}

// GET /v1/customers/{id}/attachments/{attachment_id}/download-url?disposition=attachment|inline
func (s *Server) handleDownloadURL(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := chi.URLParam(r, "id")
	attachmentID := chi.URLParam(r, "attachment_id")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	// Fetch row + tenancy check
	a, err := s.getAttachment(ctx, attachmentID)
	if err != nil {
		if err == sql.ErrNoRows {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		s.fail(w, r, http.StatusInternalServerError, "load attachment", err, "attachment_id", attachmentID)
		return
	}
	if a.OrgID != orgID || a.CustomerID != customerID {
		httpJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	// Optional: content-disposition + type
	disp := r.URL.Query().Get("disposition")
	if disp == "" {
		disp = "attachment"
	}

	reqParams := make(url.Values)
	reqParams.Set("response-content-disposition", fmt.Sprintf(`%s; filename="%s"`, disp, a.Filename))
	if a.ContentType != nil && *a.ContentType != "" {
		reqParams.Set("response-content-type", *a.ContentType)
	}

	// Presign GET
	getURL, err := s.presign.PresignedGetObject(ctx, s.bucket, a.ObjectKey, 5*time.Minute, reqParams)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "presign get", err, "attachment_id", attachmentID)
		return
	}
	httpJSON(w, http.StatusOK, downloadURLResp{URL: getURL.String()})
}

// OPTIONAL: stream through API instead of exposing MinIO host
// GET /v1/customers/{id}/attachments/{attachment_id}/download
func (s *Server) handleDownloadStream(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	customerID := chi.URLParam(r, "id")
	attachmentID := chi.URLParam(r, "attachment_id")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	a, err := s.getAttachment(ctx, attachmentID)
	if err != nil {
		if err == sql.ErrNoRows {
			httpJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		s.fail(w, r, http.StatusInternalServerError, "load attachment", err, "attachment_id", attachmentID)
		return
	}
	if a.OrgID != orgID || a.CustomerID != customerID {
		httpJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	obj, err := s.minio.GetObject(ctx, s.bucket, a.ObjectKey, minio.GetObjectOptions{})
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "get object", err, "attachment_id", attachmentID)
		return
	}
	defer obj.Close()

	if a.ContentType != nil && *a.ContentType != "" {
		w.Header().Set("Content-Type", *a.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, a.Filename))

	if _, err := io.Copy(w, obj); err != nil {
		s.log.Warnf("stream copy error: %v", err)
	}
}
