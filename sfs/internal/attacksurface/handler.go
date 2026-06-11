package attacksurface

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type DiscoverRequest struct {
	URL      string `json:"url" binding:"required"`
	MaxDepth int    `json:"max_depth"`
}

func DiscoverHandler(c *gin.Context) {
	var req DiscoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: URL is required"})
		return
	}

	depth := req.MaxDepth
	if depth <= 0 {
		depth = 2 // default depth
	}

	result, err := Discover(req.URL, depth)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
