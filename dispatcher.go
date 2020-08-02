package main

import (
	"context"
	"github.com/TykTechnologies/tyk/coprocess"
	"log"
)

// Dispatcher implementation
type Dispatcher struct{}

// Dispatch will be called on every request:
func (d *Dispatcher) Dispatch(ctx context.Context, object *coprocess.Object) (*coprocess.Object, error) {
	log.Println("Receiving object:", object)

	// We dispatch the object based on the hook name (as specified in the manifest file), these functions are in hooks.go:
	switch object.HookName {
	case "SAMLWebSSO":
		log.Println("SAMLWebSSO is called!")
		return SAMLWebSSO(object)
	}
	log.Println("Unknown hook: ", object.HookName)

	return object, nil
}

// DispatchEvent will be called when a Tyk event is triggered:
func (d *Dispatcher) DispatchEvent(ctx context.Context, event *coprocess.Event) (*coprocess.EventReply, error) {
	return &coprocess.EventReply{}, nil
}