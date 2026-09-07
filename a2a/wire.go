package a2a

import (
	"encoding/json"
	"fmt"
)

// A2A protocol generations the client can speak. ProtocolVersion10 is the default;
// ProtocolVersion03 is the pre-1.0 generation still served by 0.3-era agents.
const (
	ProtocolVersion10 = "1.0"
	ProtocolVersion03 = "0.3"
)

// wireProtocol is one A2A generation's JSON-RPC surface: the version header it
// advertises, the method name for sending a message, and the message encoding.
type wireProtocol struct {
	version       string
	versionHeader string
	sendMethod    string
}

var (
	wire10 = wireProtocol{version: ProtocolVersion10, versionHeader: "A2A-Version", sendMethod: "SendMessage"}
	wire03 = wireProtocol{version: ProtocolVersion03, versionHeader: "x-a2a-protocol-version", sendMethod: "message/send"}
)

func wireFor(version string) (wireProtocol, bool) {
	switch version {
	case ProtocolVersion10:
		return wire10, true
	case ProtocolVersion03:
		return wire03, true
	}
	return wireProtocol{}, false
}

// wireMessage is the JSON form of a Message on either wire. Kind and the role
// spelling differ between generations; the client owns the translation so callers
// see the 1.0 model (Message, Part) regardless of the target's generation.
type wireMessage struct {
	MessageID string         `json:"messageId"`
	ContextID string         `json:"contextId,omitempty"`
	TaskID    string         `json:"taskId,omitempty"`
	Role      string         `json:"role"`
	Parts     []wirePart     `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type wirePart struct {
	Kind string `json:"kind,omitempty"`
	Text string `json:"text,omitempty"`
}

var (
	roleTo03   = map[string]string{RoleUser: "user", RoleAgent: "agent"}
	roleFrom03 = map[string]string{"user": RoleUser, "agent": RoleAgent}
)

func (p wireProtocol) encodeMessage(msg Message) wireMessage {
	out := wireMessage{
		MessageID: msg.MessageID,
		ContextID: msg.ContextID,
		TaskID:    msg.TaskID,
		Role:      msg.Role,
		Parts:     make([]wirePart, 0, len(msg.Parts)),
		Metadata:  msg.Metadata,
	}
	for _, part := range msg.Parts {
		out.Parts = append(out.Parts, wirePart{Text: part.Text})
	}
	if p.version == ProtocolVersion03 {
		if r, ok := roleTo03[msg.Role]; ok {
			out.Role = r
		}
		for i := range out.Parts {
			out.Parts[i].Kind = "text"
		}
	}
	return out
}

func (p wireProtocol) decodeMessage(in wireMessage) Message {
	msg := Message{
		MessageID: in.MessageID,
		ContextID: in.ContextID,
		TaskID:    in.TaskID,
		Role:      in.Role,
		Parts:     make([]Part, 0, len(in.Parts)),
		Metadata:  in.Metadata,
	}
	if r, ok := roleFrom03[in.Role]; ok {
		msg.Role = r
	}
	for _, part := range in.Parts {
		msg.Parts = append(msg.Parts, Part{Text: part.Text})
	}
	return msg
}

// wireTask mirrors Task with the message in wire form.
type wireTask struct {
	ID        string `json:"id"`
	ContextID string `json:"contextId,omitempty"`
	Status    struct {
		State   string       `json:"state"`
		Message *wireMessage `json:"message,omitempty"`
	} `json:"status"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (p wireProtocol) decodeTask(in wireTask) *Task {
	task := &Task{ID: in.ID, ContextID: in.ContextID, Metadata: in.Metadata}
	task.Status.State = in.Status.State
	if in.Status.Message != nil {
		msg := p.decodeMessage(*in.Status.Message)
		task.Status.Message = &msg
	}
	return task
}

// sendResult is the JSON-RPC result of a send. On the 1.0 wire it is the
// SendMessageResponse oneof, {"message": ...} or {"task": ...}. On the 0.3 wire it is
// the Message or Task itself, discriminated by "kind"; some 0.3 servers wrapped it as
// {"message": ...} too, which is accepted.
type sendResult struct {
	Kind    string           `json:"kind,omitempty"`
	Message *json.RawMessage `json:"message,omitempty"`
	Task    *json.RawMessage `json:"task,omitempty"`
}

// decodeSendResult returns the message or task the agent answered with. Exactly one
// of the two is non-zero on success.
func (p wireProtocol) decodeSendResult(raw json.RawMessage) (Message, *Task, error) {
	var res sendResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return Message{}, nil, fmt.Errorf("result is not an object: %w", err)
	}

	switch {
	case res.Message != nil:
		var wm wireMessage
		if err := json.Unmarshal(*res.Message, &wm); err != nil {
			return Message{}, nil, fmt.Errorf("result.message: %w", err)
		}
		return p.decodeMessage(wm), nil, nil
	case res.Task != nil:
		var wt wireTask
		if err := json.Unmarshal(*res.Task, &wt); err != nil {
			return Message{}, nil, fmt.Errorf("result.task: %w", err)
		}
		return Message{}, p.decodeTask(wt), nil
	case res.Kind == "message":
		var wm wireMessage
		if err := json.Unmarshal(raw, &wm); err != nil {
			return Message{}, nil, fmt.Errorf("result message: %w", err)
		}
		return p.decodeMessage(wm), nil, nil
	case res.Kind == "task":
		var wt wireTask
		if err := json.Unmarshal(raw, &wt); err != nil {
			return Message{}, nil, fmt.Errorf("result task: %w", err)
		}
		return Message{}, p.decodeTask(wt), nil
	}
	return Message{}, nil, nil
}
