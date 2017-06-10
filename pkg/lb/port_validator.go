// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lb

import (
	"fmt"
)

type portSpec struct {
	name     string
	protocol string
	port     uint16
}

// PortValidator will validate a list of port definition to ensure the
// following constraints:
// - the same port name is only specified once
// - the same port number is only specified once
// - the protocol is valid (ValidateProtocol() returns true)
// - if more than one port is defined, each port must have a valid name
type PortValidator struct {
	spec []portSpec
}

// NewPortValidator returns a new port validator
func NewPortValidator() *PortValidator {
	return &PortValidator{
		spec: []portSpec{},
	}
}

// Queue schedule a port definition for validation
func (pv *PortValidator) Queue(portName string, portNumber uint16, protocol string) {
	pv.spec = append(pv.spec, portSpec{
		port:     portNumber,
		name:     portName,
		protocol: protocol,
	})
}

// Validate returns nil if the all enqueued port definition are valid as
// defined or an error
func (pv *PortValidator) Validate() error {
	portsName := map[string]bool{}
	portsNumber := map[uint16]bool{}

	for _, port := range pv.spec {
		if err := ValidateProtocol(port.protocol); err != nil {
			return err
		}

		if port.name == "" {
			if len(pv.spec) > 1 {
				return fmt.Errorf("port name must be specified if more than one port is specified")
			}

			port.name = "default"
		}

		if _, ok := portsName[port.name]; ok {
			return fmt.Errorf("port name '%s' must be unique", port.name)
		}

		if _, ok := portsNumber[port.port]; ok {
			return fmt.Errorf("port number '%d' must be unique", port.port)
		}

		portsName[port.name] = true
		portsNumber[port.port] = true
	}

	return nil
}
