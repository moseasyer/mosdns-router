package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (Policy, error) {
	var policy Policy

	file, err := os.Open(path)
	if err != nil {
		return policy, fmt.Errorf("%s: open policy: %w", path, err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		if errors.Is(err, io.EOF) {
			return policy, fmt.Errorf("%s: policy is empty", path)
		}
		return policy, fmt.Errorf("%s: decode policy: %w", path, err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return policy, fmt.Errorf("%s: policy must contain exactly one YAML document", path)
	} else if !errors.Is(err, io.EOF) {
		return policy, fmt.Errorf("%s: decode trailing content: %w", path, err)
	}

	if err := policy.Validate(); err != nil {
		return policy, fmt.Errorf("%s: validate policy: %w", path, err)
	}
	return policy, nil
}
