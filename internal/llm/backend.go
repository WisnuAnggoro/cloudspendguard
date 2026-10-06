package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"` // "system" or "user"
	Content string `json:"content"`
}

// Backend sends a chat to a model and returns the assistant's text. Tests
// substitute a stub (ScriptBackend) or a recorded fixture (ReplayBackend),
// so no unit test depends on a running model.
type Backend interface {
	Name() string
	Complete(ctx context.Context, msgs []Message) (string, error)
}

// maxResponseBytes bounds how much model output is read (denial of wallet,
// OWASP LLM10).
const maxResponseBytes = 64 << 10

var httpClient = &http.Client{Timeout: 120 * time.Second}

// OllamaBackend talks to a local Ollama server (default http://127.0.0.1:11434).
// Temperature 0 and a fixed seed make answers as repeatable as the model allows.
type OllamaBackend struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

// Name implements Backend.
func (b OllamaBackend) Name() string { return "ollama/" + b.Model }

// Complete implements Backend using POST /api/chat.
func (b OllamaBackend) Complete(ctx context.Context, msgs []Message) (string, error) {
	body := map[string]any{
		"model": b.Model, "messages": msgs, "stream": false,
		"options": map[string]any{"temperature": 0, "seed": 5910, "num_predict": 1024},
	}
	var resp struct {
		Message Message `json:"message"`
		Error   string  `json:"error"`
	}
	if err := postJSON(ctx, b.Client, strings.TrimRight(b.BaseURL, "/")+"/api/chat", nil, body, &resp); err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	if resp.Error != "" {
		return "", fmt.Errorf("ollama: %s", resp.Error)
	}
	if resp.Message.Content == "" {
		return "", errors.New("ollama: empty response")
	}
	return resp.Message.Content, nil
}

// OpenAIBackend calls an OpenAI-compatible chat completions API. It is only
// constructed when the operator opts in (Config.AllowRemote), and the engine
// forces redaction on for it.
type OpenAIBackend struct {
	BaseURL string // default https://api.openai.com/v1
	Model   string
	APIKey  string
	Client  *http.Client
}

// Name implements Backend.
func (b OpenAIBackend) Name() string { return "openai/" + b.Model }

// Complete implements Backend using POST /chat/completions.
func (b OpenAIBackend) Complete(ctx context.Context, msgs []Message) (string, error) {
	body := map[string]any{"model": b.Model, "messages": msgs, "temperature": 0, "max_tokens": 1024}
	var resp struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	hdr := map[string]string{"Authorization": "Bearer " + b.APIKey}
	if err := postJSON(ctx, b.Client, strings.TrimRight(b.BaseURL, "/")+"/chat/completions", hdr, body, &resp); err != nil {
		return "", fmt.Errorf("openai: %w", err)
	}
	if resp.Error != nil {
		return "", fmt.Errorf("openai: %s", resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("openai: empty response")
	}
	return resp.Choices[0].Message.Content, nil
}

func postJSON(ctx context.Context, c *http.Client, url string, hdr map[string]string, in, out any) error {
	if c == nil {
		c = httpClient
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

// ScriptBackend returns canned responses in order. It is the stub used by
// unit tests and by recorded fixtures.
type ScriptBackend struct {
	Label     string
	Responses []string
	mu        sync.Mutex
	calls     int
	Prompts   [][]Message // every prompt received, for assertions
}

// Name implements Backend.
func (b *ScriptBackend) Name() string { return "script/" + b.Label }

// Complete implements Backend.
func (b *ScriptBackend) Complete(_ context.Context, msgs []Message) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Prompts = append(b.Prompts, msgs)
	if b.calls >= len(b.Responses) {
		return "", errors.New("script: no more responses")
	}
	b.calls++
	return b.Responses[b.calls-1], nil
}

// Fixture is a recorded model conversation for one finding, stored as JSON
// under testdata/llm/. Record with `csg remediate --record <file>` against a
// real backend; replay with `--llm-provider replay --fixture <file>`.
type Fixture struct {
	FindingID   string   `json:"finding_id"`
	Backend     string   `json:"backend"`
	RecordedAt  string   `json:"recorded_at,omitempty"`
	Description string   `json:"description,omitempty"`
	Responses   []string `json:"responses"`
}

// LoadFixture reads a recorded fixture and returns a replaying backend.
func LoadFixture(path string) (*ScriptBackend, Fixture, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, Fixture{}, fmt.Errorf("llm: %w", err)
	}
	var f Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, Fixture{}, fmt.Errorf("llm: %s: %w", path, err)
	}
	if len(f.Responses) == 0 {
		return nil, Fixture{}, fmt.Errorf("llm: %s: fixture has no responses", path)
	}
	return &ScriptBackend{Label: "replay:" + f.Backend, Responses: f.Responses}, f, nil
}

// RecordingBackend wraps a real backend and keeps every response so it can
// be saved as a Fixture.
type RecordingBackend struct {
	Inner     Backend
	Responses []string
}

// Name implements Backend.
func (r *RecordingBackend) Name() string { return r.Inner.Name() }

// Complete implements Backend.
func (r *RecordingBackend) Complete(ctx context.Context, msgs []Message) (string, error) {
	out, err := r.Inner.Complete(ctx, msgs)
	if err == nil {
		r.Responses = append(r.Responses, out)
	}
	return out, err
}

// Save writes the recorded responses as a Fixture.
func (r *RecordingBackend) Save(path, findingID string, now time.Time) error {
	f := Fixture{FindingID: findingID, Backend: r.Inner.Name(), RecordedAt: now.UTC().Format(time.RFC3339), Responses: r.Responses}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}
