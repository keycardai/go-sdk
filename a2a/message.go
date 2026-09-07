package a2a

import (
	"crypto/rand"
	"fmt"
)

// Message roles, as the A2A 1.0 protocol names them. When the client is configured
// to speak protocol 0.3 (see WithProtocolVersion) they are translated to and from the
// 0.3 names ("user", "agent") at the wire boundary.
const (
	RoleUser  = "ROLE_USER"
	RoleAgent = "ROLE_AGENT"
)

// Part is one piece of a Message. This package models text parts only: on the A2A
// 1.0 wire a text part is {"text": ...}; on the 0.3 wire it carries a kind tag,
// {"kind": "text", "text": ...}, which the client adds and strips.
type Part struct {
	Text string `json:"text,omitempty"`
}

// Message is an A2A message exchanged with an agent: a role, an ordered list of
// content parts, optional context and task correlation, and optional metadata.
type Message struct {
	MessageID string         `json:"messageId"`
	ContextID string         `json:"contextId,omitempty"`
	TaskID    string         `json:"taskId,omitempty"`
	Role      string         `json:"role"`
	Parts     []Part         `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// TaskStatus is the state of a Task and the agent's status message, if any.
type TaskStatus struct {
	State   string   `json:"state"`
	Message *Message `json:"message,omitempty"`
}

// Task is the subset of an A2A task this package reads. A 1.0 agent may answer
// SendMessage with a task instead of a message when the work is not finished inline.
type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitempty"`
	Status    TaskStatus     `json:"status"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// AgentInterface is one entry of a 1.0 agent card's supportedInterfaces: an endpoint
// URL with the protocol binding (JSONRPC, GRPC, HTTP+JSON) and protocol version it
// serves.
type AgentInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// AgentCard is the subset of an A2A agent card this package reads. The card carries
// many more fields; only name (required) and the endpoint fields (used to resolve the
// JSON-RPC endpoint) are consumed here. A 1.0 card lists its endpoints in
// SupportedInterfaces; a 0.3 card carries a single URL and ProtocolVersion.
type AgentCard struct {
	Name                string           `json:"name"`
	Description         string           `json:"description,omitempty"`
	URL                 string           `json:"url,omitempty"`
	Version             string           `json:"version,omitempty"`
	ProtocolVersion     string           `json:"protocolVersion,omitempty"`
	SupportedInterfaces []AgentInterface `json:"supportedInterfaces,omitempty"`
}

// Result is the outcome of a delegated invocation: the agent's response and the agent
// card that was resolved for the call. A 1.0 agent answers with either a message or a
// task; exactly one of Message and Task is populated (Task is nil when the agent
// answered inline, Message is the zero value when it answered with a task).
type Result struct {
	Message   Message
	Task      *Task
	AgentCard AgentCard
}

// NewTextMessage builds a user-role message carrying a single text part, with a
// freshly generated message ID.
func NewTextMessage(text string) Message {
	return Message{
		MessageID: newUUID(),
		Role:      RoleUser,
		Parts:     []Part{{Text: text}},
	}
}

// newUUID returns a random RFC 4122 version 4 UUID string. crypto/rand.Read does not
// fail on any supported platform, so its error is not surfaced.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
