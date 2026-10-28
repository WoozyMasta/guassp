// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaBytes contains the generated runtime validation schema.
//
//go:embed generated/guassp.schema.json
var schemaBytes []byte

// exampleYAML contains the generated minimal configuration template.
//
//go:embed generated/guassp.example.yaml
var exampleYAML []byte

// Schema compilation state is shared because the embedded schema is immutable.
var (
	schemaOnce       sync.Once
	compiledSchema   *jsonschema.Schema
	schemaCompileErr error
)

// schemaURL identifies the embedded config schema to the compiler.
const schemaURL = "urn:guassp:config"

// rejectExternalSchemaLoader prevents runtime schema resource access.
type rejectExternalSchemaLoader struct{}

var _ jsonschema.URLLoader = rejectExternalSchemaLoader{}

// ExampleYAML returns the minimal config template used for explicit bootstrap.
func ExampleYAML() string {
	return string(exampleYAML)
}

// Load rejects schema references outside the embedded resource.
func (rejectExternalSchemaLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema resource %q is disabled", location)
}

// validateSchema checks the effective configuration against the embedded schema.
func validateSchema(config Config) error {
	schemaOnce.Do(compileSchema)
	if schemaCompileErr != nil {
		return fmt.Errorf("compile embedded schema: %w", schemaCompileErr)
	}

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return fmt.Errorf("decode config instance: %w", err)
	}
	if err := compiledSchema.Validate(instance); err != nil {
		return fmt.Errorf("config does not match schema: %w", err)
	}

	return nil
}

// compileSchema parses and compiles the generated schema once per process.
func compileSchema() {
	var document any
	if err := json.Unmarshal(schemaBytes, &document); err != nil {
		schemaCompileErr = fmt.Errorf("decode embedded schema: %w", err)
		return
	}

	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(rejectExternalSchemaLoader{})
	if err := compiler.AddResource(schemaURL, document); err != nil {
		schemaCompileErr = fmt.Errorf("add embedded schema: %w", err)
		return
	}

	compiledSchema, schemaCompileErr = compiler.Compile(schemaURL)
}
