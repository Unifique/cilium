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

package k8s

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/lb"

	"k8s.io/client-go/pkg/api/v1"
)

// K8sServiceID is what uniquely identifies a Kubernetes service within a
// cluster. A service name is unique inside a namespace.
type K8sServiceID struct {
	Name      string
	Namespace string
}

// NewK8sServiceID derives the ID of a k8s service from its spec
func NewK8sServiceID(svc *v1.Service) K8sServiceID {
	return K8sServiceID{
		Name:      svc.Name,
		Namespace: svc.Namespace,
	}
}

// String returns the human readable version of a service ID
func (s *K8sServiceID) String() string {
	return s.Namespace + "/" + s.Name
}

// Equal returns true if both services IDs are equal
func (s *K8sServiceID) Equal(o K8sServiceID) bool {
	return s.Name == o.Name && s.Namespace == o.Namespace
}

// K8sService is the internal representation of a Kubernetes service
type K8sService struct {
	// ID identifies a Kubernetes services
	ID K8sServiceID

	// Frontends is the list of frontend configurations
	Frontends []lb.Frontend

	// Modified is true when the service must be synchronized with the
	// datapath
	Modified bool

	// Deleted is true if the service has been marked for deletion
	Deleted bool
}

func validateServicePorts(svc *v1.Service) error {
	validator := lb.NewPortValidator()
	for _, port := range svc.Spec.Ports {
		validator.Queue(port.Name, uint16(port.Port), string(port.Protocol))
	}

	return validator.Validate()
}

func newClusterIP(svc *v1.Service) ([]lb.Frontend, error) {
	list := []lb.Frontend{}

	ip, err := lb.ParseServiceIP(svc.Spec.ClusterIP)
	if err != nil {
		return nil, fmt.Errorf("invalid ClusterIP: %s", err)
	}

	for _, port := range svc.Spec.Ports {
		frontend := lb.Frontend{
			IP:       ip,
			Protocol: lb.NormalizeProtocol(string(port.Protocol)),
			Port:     uint16(port.Port),
		}
		list = append(list, frontend)
	}

	return list, nil
}

// ParseK8sService validates and parses a Kubernets service, returns:
//  - A valid K8sService with n frontends
//  - nil if no service needs to be configured (headless service)
//  - error if the spec contained an error
func ParseK8sService(svc *v1.Service) (*K8sService, error) {
	service := &K8sService{
		ID: NewK8sServiceID(svc),
	}

	if err := validateServicePorts(svc); err != nil {
		return nil, err
	}

	switch svc.Spec.Type {
	case v1.ServiceTypeClusterIP:
		if strings.ToLower(svc.Spec.ClusterIP) == "none" || svc.Spec.ClusterIP == "" {
			return nil, nil
		}

		list, err := newClusterIP(svc)
		if err != nil {
			return nil, err
		}
		service.Frontends = list

	default:
		return nil, fmt.Errorf("unsupported type %s", svc.Spec.Type)
	}

	return service, nil
}
