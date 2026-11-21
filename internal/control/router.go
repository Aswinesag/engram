package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"engram/internal/mcp"
)

const defaultHTTPTimeout = 5 * time.Minute

// Role represents a normalized chat message role across model providers.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ToolCall represents a single model-requested MCP tool invocation.
type ToolCall struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// Message is the provider-agnostic conversation message exchanged in the agent loop.
type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolName   string     `json:"tool_name,omitempty"`
	IsError    bool       `json:"is_error,omitempty"`
}

// ChatRequest encapsulates a single turn sent to an LLM provider.
type ChatRequest struct {
	SystemPrompt string
	Messages     []Message
	Tools        []mcp.ToolDefinition
}

// ChatResponse captures the assembled response, tool calls, and token usage from a stream.
type ChatResponse struct {
	Content    string
	ToolCalls  []ToolCall
	StopReason string
	TokensIn   int64
	TokensOut  int64
}

// StreamDeltaHandler receives incremental assistant text chunks while streaming.
type StreamDeltaHandler func(textDelta string)

// ModelRouter communicates directly over net/http with Anthropic, OpenAI, and Ollama
// using raw SSE and NDJSON streaming parsers (zero external orchestration wrappers).
type ModelRouter struct {
	cfg        ModelConfig
	apiKey     string
	httpClient *http.Client
}

// NewModelRouter constructs a ModelRouter from .engram/config.toml model settings.
// apiKeyOverride is optional; if empty, the environment variable named in cfg.APIKeyEnv is read.
func NewModelRouter(cfg ModelConfig, apiKeyOverride string, httpClient *http.Client) (*ModelRouter, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		cfg.Endpoint = defaultEndpointForProvider(cfg.Provider)
	}
	if cfg.MaxOutputTokens <= 0 {
		cfg.MaxOutputTokens = 8192
	}

	apiKey := strings.TrimSpace(apiKeyOverride)
	if apiKey == "" && strings.TrimSpace(cfg.APIKeyEnv) != "" {
		apiKey = strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
	}

	if apiKey == "" && cfg.Provider != "ollama" && !isLocalEndpoint(cfg.Endpoint) {
		return nil, fmt.Errorf("control: missing API key in environment variable %q for provider %q",
			cfg.APIKeyEnv, cfg.Provider)
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	return &ModelRouter{
		cfg:        cfg,
		apiKey:     apiKey,
		httpClient: httpClient,
	}, nil
}

// StreamChat dispatches req to the configured provider and streams its response.
func (r *ModelRouter) StreamChat(ctx context.Context, req ChatRequest, onDelta StreamDeltaHandler) (ChatResponse, error) {
	switch r.cfg.Provider {
	case "anthropic":
		return r.streamAnthropic(ctx, req, onDelta)
	case "openai":
		return r.streamOpenAI(ctx, req, onDelta)
	case "ollama":
		return r.streamOllama(ctx, req, onDelta)
	default:
		return ChatResponse{}, fmt.Errorf("control: unsupported provider %q", r.cfg.Provider)
	}
}

func defaultEndpointForProvider(provider string) string {
	switch provider {
	case "anthropic":
		return "https://api.anthropic.com/v1/messages"
	case "openai":
		return "https://api.openai.com/v1/chat/completions"
	case "ollama":
		return "http://127.0.0.1:11434/api/chat"
	default:
		return ""
	}
}

func isLocalEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// --- Anthropic Messages API (SSE) ---

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
	Tools     []anthropicTool    `json:"tools,omitempty"`
	Stream    bool               `json:"stream"`
}

type anthropicMessage struct {
	Role    string                  `json:"role"`
	Content []anthropicContentBlock `json:"content"`
}

type anthropicContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

func (r *ModelRouter) streamAnthropic(ctx context.Context, req ChatRequest, onDelta StreamDeltaHandler) (ChatResponse, error) {
	payload := anthropicRequest{
		Model:     r.cfg.Model,
		MaxTokens: r.cfg.MaxOutputTokens,
		System:    req.SystemPrompt,
		Messages:  encodeAnthropicMessages(req.Messages),
		Tools:     encodeAnthropicTools(req.Tools),
		Stream:    true,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: marshal anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: create anthropic http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	if r.apiKey != "" {
		httpReq.Header.Set("x-api-key", r.apiKey)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return ChatResponse{}, fmt.Errorf("control: anthropic HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	return parseAnthropicSSE(resp.Body, onDelta)
}

func encodeAnthropicMessages(msgs []Message) []anthropicMessage {
	out := make([]anthropicMessage, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			out = append(out, anthropicMessage{
				Role:    "user",
				Content: []anthropicContentBlock{{Type: "text", Text: m.Content}},
			})
		case RoleAssistant:
			var blocks []anthropicContentBlock
			if m.Content != "" {
				blocks = append(blocks, anthropicContentBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				in := tc.Input
				if len(bytes.TrimSpace(in)) == 0 {
					in = json.RawMessage(`{}`)
				}
				blocks = append(blocks, anthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: in,
				})
			}
			if len(blocks) > 0 {
				out = append(out, anthropicMessage{Role: "assistant", Content: blocks})
			}
		case RoleTool:
			block := anthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   m.Content,
				IsError:   m.IsError,
			}
			// Anthropic requires consecutive tool_result blocks to be grouped inside a single user turn.
			if len(out) > 0 && out[len(out)-1].Role == "user" &&
				len(out[len(out)-1].Content) > 0 && out[len(out)-1].Content[0].Type == "tool_result" {
				out[len(out)-1].Content = append(out[len(out)-1].Content, block)
			} else {
				out = append(out, anthropicMessage{
					Role:    "user",
					Content: []anthropicContentBlock{block},
				})
			}
		}
	}
	return out
}

func encodeAnthropicTools(tools []mcp.ToolDefinition) []anthropicTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]anthropicTool, 0, len(tools))
	for _, t := range tools {
		schema := t.InputSchema
		if len(bytes.TrimSpace(schema)) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, anthropicTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema,
		})
	}
	return out
}

type anthropicBlockAcc struct {
	blockType string
	id        string
	name      string
	rawInput  strings.Builder
}

func parseAnthropicSSE(r io.Reader, onDelta StreamDeltaHandler) (ChatResponse, error) {
	var (
		res    ChatResponse
		text   strings.Builder
		blocks = make(map[int]*anthropicBlockAcc)
	)

	err := readSSEEvents(r, func(eventName, data string) error {
		if data == "" || data == "[DONE]" {
			return nil
		}

		var ev struct {
			Type    string `json:"type"`
			Message struct {
				Usage struct {
					InputTokens int64 `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Index        int `json:"index"`
			ContentBlock struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int64 `json:"output_tokens"`
			} `json:"usage"`
			Error *struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			return fmt.Errorf("control: decode anthropic SSE event %q: %w", eventName, err)
		}

		evType := ev.Type
		if evType == "" {
			evType = eventName
		}

		switch evType {
		case "error":
			if ev.Error != nil {
				return fmt.Errorf("control: anthropic stream error (%s): %s", ev.Error.Type, ev.Error.Message)
			}
			return errors.New("control: anthropic stream error")
		case "message_start":
			res.TokensIn += ev.Message.Usage.InputTokens
		case "content_block_start":
			acc := &anthropicBlockAcc{
				blockType: ev.ContentBlock.Type,
				id:        ev.ContentBlock.ID,
				name:      ev.ContentBlock.Name,
			}
			if len(bytes.TrimSpace(ev.ContentBlock.Input)) > 0 && string(bytes.TrimSpace(ev.ContentBlock.Input)) != "{}" {
				acc.rawInput.Write(ev.ContentBlock.Input)
			}
			blocks[ev.Index] = acc
		case "content_block_delta":
			switch ev.Delta.Type {
			case "text_delta":
				if ev.Delta.Text != "" {
					text.WriteString(ev.Delta.Text)
					if onDelta != nil {
						onDelta(ev.Delta.Text)
					}
				}
			case "input_json_delta":
				if acc, ok := blocks[ev.Index]; ok {
					acc.rawInput.WriteString(ev.Delta.PartialJSON)
				}
			}
		case "message_delta":
			if ev.Delta.StopReason != "" {
				res.StopReason = ev.Delta.StopReason
			}
			if ev.Usage.OutputTokens > 0 {
				res.TokensOut = ev.Usage.OutputTokens
			}
		}
		return nil
	})
	if err != nil {
		return ChatResponse{}, err
	}

	res.Content = text.String()

	indices := make([]int, 0, len(blocks))
	for idx := range blocks {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	for _, idx := range indices {
		acc := blocks[idx]
		if acc.blockType != "tool_use" {
			continue
		}
		raw := strings.TrimSpace(acc.rawInput.String())
		if raw == "" {
			raw = "{}"
		}
		if !json.Valid([]byte(raw)) {
			return ChatResponse{}, fmt.Errorf("control: anthropic tool %q produced invalid JSON input: %s", acc.name, raw)
		}
		res.ToolCalls = append(res.ToolCalls, ToolCall{
			ID:    acc.id,
			Name:  acc.name,
			Input: json.RawMessage(raw),
		})
	}

	return res, nil
}

// --- OpenAI Chat Completions API (SSE) ---

type openAIRequest struct {
	Model         string          `json:"model"`
	MaxTokens     int             `json:"max_tokens,omitempty"`
	Messages      []openAIMessage `json:"messages"`
	Tools         []openAITool    `json:"tools,omitempty"`
	Stream        bool            `json:"stream"`
	StreamOptions *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options,omitempty"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAITool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

func (r *ModelRouter) streamOpenAI(ctx context.Context, req ChatRequest, onDelta StreamDeltaHandler) (ChatResponse, error) {
	payload := openAIRequest{
		Model:     r.cfg.Model,
		MaxTokens: r.cfg.MaxOutputTokens,
		Messages:  encodeOpenAIMessages(req.SystemPrompt, req.Messages),
		Tools:     encodeOpenAITools(req.Tools),
		Stream:    true,
		StreamOptions: &struct {
			IncludeUsage bool `json:"include_usage"`
		}{IncludeUsage: true},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: marshal openai request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: create openai http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if r.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.apiKey)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: openai request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return ChatResponse{}, fmt.Errorf("control: openai HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	return parseOpenAISSE(resp.Body, onDelta)
}

func encodeOpenAIMessages(systemPrompt string, msgs []Message) []openAIMessage {
	var out []openAIMessage
	if strings.TrimSpace(systemPrompt) != "" {
		out = append(out, openAIMessage{Role: "system", Content: systemPrompt})
	}
	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			out = append(out, openAIMessage{Role: "user", Content: m.Content})
		case RoleAssistant:
			msg := openAIMessage{Role: "assistant", Content: m.Content}
			for _, tc := range m.ToolCalls {
				args := strings.TrimSpace(string(tc.Input))
				if args == "" {
					args = "{}"
				}
				otc := openAIToolCall{ID: tc.ID, Type: "function"}
				otc.Function.Name = tc.Name
				otc.Function.Arguments = args
				msg.ToolCalls = append(msg.ToolCalls, otc)
			}
			out = append(out, msg)
		case RoleTool:
			out = append(out, openAIMessage{
				Role:       "tool",
				ToolCallID: m.ToolCallID,
				Content:    m.Content,
			})
		}
	}
	return out
}

func encodeOpenAITools(tools []mcp.ToolDefinition) []openAITool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]openAITool, 0, len(tools))
	for _, t := range tools {
		schema := t.InputSchema
		if len(bytes.TrimSpace(schema)) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		var ot openAITool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = schema
		out = append(out, ot)
	}
	return out
}

type openAIToolAcc struct {
	id   string
	name string
	args strings.Builder
}

func parseOpenAISSE(r io.Reader, onDelta StreamDeltaHandler) (ChatResponse, error) {
	var (
		res       ChatResponse
		text      strings.Builder
		toolCalls = make(map[int]*openAIToolAcc)
	)

	err := readSSEEvents(r, func(_, data string) error {
		if data == "" || data == "[DONE]" {
			return nil
		}

		var chunk struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int64 `json:"prompt_tokens"`
				CompletionTokens int64 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return fmt.Errorf("control: decode openai SSE chunk: %w", err)
		}
		if chunk.Error != nil {
			return fmt.Errorf("control: openai stream error: %s", chunk.Error.Message)
		}
		if chunk.Usage != nil {
			res.TokensIn = chunk.Usage.PromptTokens
			res.TokensOut = chunk.Usage.CompletionTokens
		}

		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				text.WriteString(ch.Delta.Content)
				if onDelta != nil {
					onDelta(ch.Delta.Content)
				}
			}
			for _, tc := range ch.Delta.ToolCalls {
				acc, ok := toolCalls[tc.Index]
				if !ok {
					acc = &openAIToolAcc{}
					toolCalls[tc.Index] = acc
				}
				if tc.ID != "" {
					acc.id = tc.ID
				}
				if tc.Function.Name != "" {
					acc.name = tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					acc.args.WriteString(tc.Function.Arguments)
				}
			}
			if ch.FinishReason != "" {
				res.StopReason = ch.FinishReason
			}
		}
		return nil
	})
	if err != nil {
		return ChatResponse{}, err
	}

	res.Content = text.String()

	indices := make([]int, 0, len(toolCalls))
	for idx := range toolCalls {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	for _, idx := range indices {
		acc := toolCalls[idx]
		raw := strings.TrimSpace(acc.args.String())
		if raw == "" {
			raw = "{}"
		}
		if !json.Valid([]byte(raw)) {
			return ChatResponse{}, fmt.Errorf("control: openai tool %q produced invalid JSON arguments: %s", acc.name, raw)
		}
		id := acc.id
		if id == "" {
			id = fmt.Sprintf("call_%d", idx)
		}
		res.ToolCalls = append(res.ToolCalls, ToolCall{
			ID:    id,
			Name:  acc.name,
			Input: json.RawMessage(raw),
		})
	}

	return res, nil
}

// --- Ollama Native Chat API (NDJSON Stream) ---

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Tools    []openAITool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"`
}

type ollamaToolCall struct {
	ID       string `json:"id,omitempty"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

func (r *ModelRouter) streamOllama(ctx context.Context, req ChatRequest, onDelta StreamDeltaHandler) (ChatResponse, error) {
	payload := ollamaRequest{
		Model:    r.cfg.Model,
		Messages: encodeOllamaMessages(req.SystemPrompt, req.Messages),
		Tools:    encodeOpenAITools(req.Tools),
		Stream:   true,
		Options: map[string]any{
			"num_predict": r.cfg.MaxOutputTokens,
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: marshal ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: create ollama http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.apiKey)
	}

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("control: ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return ChatResponse{}, fmt.Errorf("control: ollama HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	return parseOllamaNDJSON(resp.Body, onDelta)
}

func encodeOllamaMessages(systemPrompt string, msgs []Message) []ollamaMessage {
	var out []ollamaMessage
	if strings.TrimSpace(systemPrompt) != "" {
		out = append(out, ollamaMessage{Role: "system", Content: systemPrompt})
	}
	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			out = append(out, ollamaMessage{Role: "user", Content: m.Content})
		case RoleAssistant:
			om := ollamaMessage{Role: "assistant", Content: m.Content}
			for _, tc := range m.ToolCalls {
				in := tc.Input
				if len(bytes.TrimSpace(in)) == 0 {
					in = json.RawMessage(`{}`)
				}
				var otc ollamaToolCall
				otc.ID = tc.ID
				otc.Function.Name = tc.Name
				otc.Function.Arguments = in
				om.ToolCalls = append(om.ToolCalls, otc)
			}
			out = append(out, om)
		case RoleTool:
			out = append(out, ollamaMessage{
				Role:     "tool",
				Content:  m.Content,
				ToolName: m.ToolName,
			})
		}
	}
	return out
}

func parseOllamaNDJSON(r io.Reader, onDelta StreamDeltaHandler) (ChatResponse, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var (
		res  ChatResponse
		text strings.Builder
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var chunk struct {
			Error           string `json:"error"`
			Done            bool   `json:"done"`
			DoneReason      string `json:"done_reason"`
			PromptEvalCount int64  `json:"prompt_eval_count"`
			EvalCount       int64  `json:"eval_count"`
			Message         struct {
				Content   string           `json:"content"`
				ToolCalls []ollamaToolCall `json:"tool_calls"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			return ChatResponse{}, fmt.Errorf("control: decode ollama stream chunk: %w", err)
		}
		if chunk.Error != "" {
			return ChatResponse{}, fmt.Errorf("control: ollama stream error: %s", chunk.Error)
		}
		if chunk.Message.Content != "" {
			text.WriteString(chunk.Message.Content)
			if onDelta != nil {
				onDelta(chunk.Message.Content)
			}
		}
		for i, tc := range chunk.Message.ToolCalls {
			args := tc.Function.Arguments
			if len(bytes.TrimSpace(args)) == 0 {
				args = json.RawMessage(`{}`)
			}
			id := tc.ID
			if id == "" {
				id = fmt.Sprintf("ollama_call_%d_%d", len(res.ToolCalls), i)
			}
			res.ToolCalls = append(res.ToolCalls, ToolCall{
				ID:    id,
				Name:  tc.Function.Name,
				Input: args,
			})
		}
		if chunk.Done {
			if chunk.DoneReason != "" {
				res.StopReason = chunk.DoneReason
			}
			res.TokensIn = chunk.PromptEvalCount
			res.TokensOut = chunk.EvalCount
		}
	}
	if err := scanner.Err(); err != nil {
		return ChatResponse{}, fmt.Errorf("control: read ollama stream: %w", err)
	}

	res.Content = text.String()
	return res, nil
}

// readSSEEvents parses standard Server-Sent Events frames separated by blank lines.
func readSSEEvents(r io.Reader, handle func(eventName, data string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var (
		eventName string
		dataLines []string
	)

	flush := func() error {
		if len(dataLines) == 0 && eventName == "" {
			return nil
		}
		data := strings.Join(dataLines, "\n")
		ev := eventName
		eventName = ""
		dataLines = dataLines[:0]
		return handle(ev, data)
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, val, hasColon := strings.Cut(line, ":")
		if hasColon {
			val = strings.TrimPrefix(val, " ")
		}
		switch field {
		case "event":
			eventName = val
		case "data":
			dataLines = append(dataLines, val)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("control: read SSE stream: %w", err)
	}
	return flush()
}
