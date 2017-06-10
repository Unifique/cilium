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
	"net"

	"github.com/cilium/cilium/pkg/lb"

	. "gopkg.in/check.v1"
	"k8s.io/client-go/pkg/api/v1"
)

var _ = Suite(&K8sSuite{})

func (s *K8sSuite) TestParseK8sService(c *C) {
	// invalid ClusterIP
	_, err := ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "invalid"}})
	c.Assert(err, Not(IsNil))

	// invalid ClusterIP IPv4
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "10..1.1.1"}})
	c.Assert(err, Not(IsNil))

	// invalid ClusterIP IPv6
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "b44d:::1"}})
	c.Assert(err, Not(IsNil))

	// invalid ServiceType
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceType("invalid")}})
	c.Assert(err, Not(IsNil))

	// unsupported type: NodePort
	// FIXME
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeNodePort}})
	c.Assert(err, Not(IsNil))

	// unsupported type: LoadBalancer
	// FIXME
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer}})
	c.Assert(err, Not(IsNil))

	// unsupported type: ExternalName
	// FIXME
	_, err = ParseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeExternalName}})
	c.Assert(err, Not(IsNil))

	// headless service
	svc, err := ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "NONE",
		},
	})
	c.Assert(err, IsNil)
	c.Assert(svc, IsNil)

	// valid IPv4 ClusterIP, no ports
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "10.1.1.1",
		},
	})
	c.Assert(err, IsNil)

	// valid IPv6 ClusterIP, no ports
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "f00d::1",
		},
	})
	c.Assert(err, IsNil)

	// Missing port name for multiple ports
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: ""},
				{Name: ""},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Missing name for single port is valid
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "", Protocol: "TCP"},
			},
		},
	})
	c.Assert(err, IsNil)

	// Unknown protocol
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Protocol: "unknown_proto"},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Missing protocol
	_, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Protocol: ""},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Valid ClusterIP with two ports
	svc, err = ParseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
				{Name: "https", Port: 443, Protocol: "TCP"},
			},
		},
	})
	c.Assert(err, IsNil)
	c.Assert(svc.Frontends[0].IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(svc.Frontends[0].Port, Equals, uint16(80))
	c.Assert(svc.Frontends[0].Protocol, Equals, lb.TCP)
	c.Assert(svc.Frontends[1].IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(svc.Frontends[1].Port, Equals, uint16(443))
	c.Assert(svc.Frontends[1].Protocol, Equals, lb.TCP)
}

func (s *K8sSuite) TestServiceIDEqual(c *C) {
	id1 := &K8sServiceID{Name: "foo", Namespace: "foo"}
	id2 := &K8sServiceID{Name: "bar", Namespace: "foo"}
	id3 := &K8sServiceID{Name: "foo", Namespace: "bar"}

	tests := []struct {
		a      *K8sServiceID
		b      *K8sServiceID
		result bool
	}{
		{id1, id1, true}, {id1, id2, false}, {id1, id3, false},
		{id2, id1, false}, {id2, id2, true}, {id2, id3, false},
		{id3, id1, false}, {id3, id2, false}, {id3, id3, true},
	}

	for _, test := range tests {
		c.Assert(test.a.Equal(test.b), Equals, test.result)
	}
}
