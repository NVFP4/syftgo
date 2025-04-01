package server

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/yashgorana/syftbox-go/internal/blob"
	"github.com/yashgorana/syftbox-go/internal/datasite"
	"github.com/yashgorana/syftbox-go/internal/server/auth"
	"github.com/yashgorana/syftbox-go/internal/server/middlewares"
	blobHandler "github.com/yashgorana/syftbox-go/internal/server/v1/blob"
	datasiteHandler "github.com/yashgorana/syftbox-go/internal/server/v1/datasite"
	wsV1 "github.com/yashgorana/syftbox-go/internal/server/v1/ws"
	"github.com/yashgorana/syftbox-go/internal/version"

	_ "embed"
)

//go:embed templates/install.sh
var installScript string

var jwtSecret = os.Getenv("SYFTBOX_JWT_SECRET")

func SetupRoutes(hub *wsV1.WebsocketHub, svcBlob *blob.BlobService, svcDatasite *datasite.DatasiteService) http.Handler {
	r := gin.Default()

	blob := blobHandler.New(svcBlob)
	ds := datasiteHandler.New(svcDatasite)
	auth := auth.New(auth.AuthConfig{
		JwtSecret:      jwtSecret,
		JwtExpiry:      168 * time.Hour, // 1 day
		EmailOTPLength: 8,               // 8 digit
		EmailOTPExpiry: 5 * time.Minute,
	})

	r.Use(gzip.Gzip(gzip.BestSpeed))
	r.Use(cors.Default())

	r.GET("/", IndexHandler)
	r.GET("/healthz", HealthHandler)
	r.GET("/install.sh", InstallHeader)
	r.StaticFS("/releases", http.Dir("./releases"))

	r.GET("/auth/login", auth.Login)
	r.GET("/auth/verify", auth.Verify)

	v1 := r.Group("/api/v1")
	v1.Use(middlewares.JwtAuth(jwtSecret)) // enforce auth on v1 routes
	{
		// blob
		v1.GET("/blob/list", blob.List)
		v1.GET("/blob/upload", blob.Upload)
		v1.GET("/blob/download", blob.Download)
		v1.POST("/blob/complete", blob.Complete)

		// datasite
		v1.GET("/datasite/view", ds.GetView)
		v1.POST("/datasite/download", ds.DownloadFiles)

		// websocket events
		v1.GET("/events", hub.WebsocketHandler)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "not found",
		})
	})

	r.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"error": "method not allowed",
		})
	})

	return r.Handler()
}

func IndexHandler(ctx *gin.Context) {
	// return a plaintext
	ctx.String(http.StatusOK, version.DetailedWithApp())
}

func HealthHandler(ctx *gin.Context) {
	ctx.PureJSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

func InstallHeader(ctx *gin.Context) {
	ctx.Header("Content-Type", "application/x-sh")
	ctx.Header("Content-Disposition", "attachment; filename=install.sh")
	ctx.String(http.StatusOK, installScript)
}

func init() {
	gin.SetMode(gin.ReleaseMode)
}
