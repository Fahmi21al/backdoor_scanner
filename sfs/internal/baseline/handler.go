package baseline

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) CreateBaseline(c *gin.Context) {
	var req struct {
		ProjectID  string `json:"projectId" binding:"required"`
		Name       string `json:"name" binding:"required"`
		SourcePath string `json:"sourcePath" binding:"required"`
		Version    string `json:"version"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	b := &Baseline{
		ProjectID:  req.ProjectID,
		Name:       req.Name,
		SourcePath: req.SourcePath,
		Version:    req.Version,
	}

	if err := h.repo.Create(b); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, b)
}

func (h *Handler) GetBaselines(c *gin.Context) {
	baselines, err := h.repo.GetAll()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, baselines)
}
