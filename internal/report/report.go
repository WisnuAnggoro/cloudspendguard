// Package report renders a prioritized backlog of findings as Markdown,
// HTML, JSON, or SARIF (for GitHub/GitLab code-scanning integration).
//
// Scaffolded in Unit 2 (Week 2). Renderers land in Unit 6 (Week 6),
// tagged v0.6.0-beta, alongside end-to-end integration and evaluation.
package report

import (
	"errors"
	"io"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// ErrNotImplemented is returned by stubs until the Week 6 implementation lands.
var ErrNotImplemented = errors.New("report: not implemented until Week 6 (v0.6.0-beta)")

// Format is an output report format.
type Format string

const (
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif" // https://sarifweb.azurewebsites.net/
)

// Renderer writes a prioritized findings backlog to w in one Format.
type Renderer interface {
	Render(w io.Writer, findings []models.Finding) error
}

// NewRenderer returns the Renderer for format. It currently returns a stub
// that reports ErrNotImplemented for every format.
func NewRenderer(format Format) (Renderer, error) {
	switch format {
	case FormatMarkdown, FormatHTML, FormatJSON, FormatSARIF:
		return stubRenderer{}, nil
	default:
		return nil, errors.New("report: unknown format " + string(format))
	}
}

type stubRenderer struct{}

func (stubRenderer) Render(_ io.Writer, _ []models.Finding) error {
	return ErrNotImplemented
}
