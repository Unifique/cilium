#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

export 'KUBERNETES_MASTER_IP4'=${KUBERNETES_MASTER_IP4:-"192.168.33.11"}
export 'KUBERNETES_MASTER_IP6'=${KUBERNETES_MASTER_IP6:-"FD01::B"}
export 'KUBERNETES_NODE_2_IP4'=${KUBERNETES_NODE_2_IP4:-"192.168.33.12"}
export 'KUBERNETES_NODE_2_IP6'=${KUBERNETES_NODE_2_IP6:-"FD01::C"}
export 'KUBERNETES_MASTER_SVC_IP4'=${KUBERNETES_MASTER_SVC_IP4:-"172.20.0.1"}
export 'KUBERNETES_MASTER_SVC_IP6'=${KUBERNETES_MASTER_SVC_IP6:-"FD03::1"}
export 'cluster_name'=${cluster_name:-"cilium-k8s-tests"}

if [ -z "$(command -v cfssl)" ]; then
    echo "cfssl not found, please download it from"
    echo "https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
    echo "and add it to your PATH."
    exit -1
fi

if [ -z "$(command -v cfssljson)" ]; then
    echo "cfssljson not found, please download it from"
    echo "https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
    echo "and add it to your PATH."
    exit -1
fi

cat > "${dir}/ca-config.json" <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat > "${dir}/ca-csr.json" <<EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert -initca "${dir}/ca-csr.json" | cfssljson -bare "${dir}/ca"

cat > "${dir}/admin-csr.json" <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:masters",
      "OU": "Cluster",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca="${dir}/ca.pem" \
  -ca-key="${dir}/ca-key.pem" \
  -config="${dir}/ca-config.json" \
  -profile=kubernetes \
  "${dir}/admin-csr.json" | cfssljson -bare "${dir}/admin"

cat > "${dir}/kubernetes-csr.json" <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "${KUBERNETES_MASTER_IP4}",
    "${KUBERNETES_MASTER_IP6}",
    "${KUBERNETES_MASTER_SVC_IP4}",
    "${KUBERNETES_MASTER_SVC_IP6}",
    "127.0.0.1",
    "::1",
    "localhost",
    "${cluster_name}.default"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Cluster",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca="${dir}/ca.pem" \
  -ca-key="${dir}/ca-key.pem" \
  -config="${dir}/ca-config.json" \
  -profile=kubernetes \
  "${dir}/kubernetes-csr.json" | cfssljson -bare "${dir}/kubernetes"

cat > "${dir}/cilium-k8s-master.json" <<EOF
{
  "CN": "system:node:cilium-k8s-master",
  "hosts": [
    "${KUBERNETES_MASTER_IP4}",
    "${KUBERNETES_MASTER_IP6}",
    "127.0.0.1",
    "::1",
    "localhost",
    "cilium-k8s-master"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Cluster",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca="${dir}/ca.pem" \
  -ca-key="${dir}/ca-key.pem" \
  -config="${dir}/ca-config.json" \
  -profile=kubernetes \
  "${dir}/cilium-k8s-master.json" | cfssljson -bare "${dir}/cilium-k8s-master"

cat > "${dir}/cilium-k8s-node-2.json" <<EOF
{
  "CN": "system:node:cilium-k8s-node-2",
  "hosts": [
    "${KUBERNETES_NODE_2_IP4}",
    "${KUBERNETES_NODE_2_IP6}",
    "127.0.0.1",
    "::1",
    "localhost",
    "cilium-k8s-node-2"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Cluster",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca="${dir}/ca.pem" \
  -ca-key="${dir}/ca-key.pem" \
  -config="${dir}/ca-config.json" \
  -profile=kubernetes \
  "${dir}/cilium-k8s-node-2.json" | cfssljson -bare "${dir}/cilium-k8s-node-2"

BOOTSTRAP_TOKEN=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')

cat > "${dir}/token.csv" <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF

rm "${dir}/ca-config.json" \
   "${dir}/ca-csr.json" \
   "${dir}/admin-csr.json" \
   "${dir}/kubernetes-csr.json" \
   "${dir}/cilium-k8s-master.json" \
   "${dir}/cilium-k8s-node-2.json"
