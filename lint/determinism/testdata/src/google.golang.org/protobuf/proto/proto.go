// Package proto stubs the real protobuf runtime so analysistest can resolve
// the fully-qualified name without the analyzer module depending on protobuf.
package proto

type Message interface{}

func Marshal(Message) ([]byte, error) { return nil, nil }

type MarshalOptions struct{ Deterministic bool }

func (MarshalOptions) Marshal(Message) ([]byte, error) { return nil, nil }
