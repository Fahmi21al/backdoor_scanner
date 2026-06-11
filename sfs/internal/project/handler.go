package project

import (
	"net/http"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) CreateProject(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		TargetType   string `json:"targetType" binding:"required"`
		TargetPath   string `json:"targetPath" binding:"required"`
		BaselinePath string `json:"baselinePath"`
		DbDumpPath   string `json:"dbDumpPath"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p := &Project{
		Name:         req.Name,
		TargetType:   req.TargetType,
		TargetPath:   req.TargetPath,
		BaselinePath: req.BaselinePath,
		DbDumpPath:   req.DbDumpPath,
	}

	if err := h.repo.Create(p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, p)
}

func (h *Handler) GetProjects(c *gin.Context) {
	projects, err := h.repo.GetAll()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, projects)
}

func (h *Handler) GetProject(c *gin.Context) {
	id := c.Param("id")
	project, err := h.repo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}
	c.JSON(http.StatusOK, project)
}

func (h *Handler) DeleteProject(c *gin.Context) {
	id := c.Param("id")
	if err := h.repo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Project deleted successfully"})
}

func (h *Handler) PickPath(c *gin.Context) {
	kind := c.Query("type") // "folder" or "file"
	var cmdStr string
	if kind == "folder" {
		cmdStr = `Add-Type -AssemblyName System.windows.forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }`
	} else {
		cmdStr = `Add-Type -AssemblyName System.windows.forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Filter = "SQL Files (*.sql)|*.sql|All Files (*.*)|*.*"; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.FileName }`
	}

	cmd := exec.Command("powershell", "-NoProfile", "-Command", cmdStr)
	out, err := cmd.Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "output": string(out)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"path": strings.TrimSpace(string(out))})
}
