{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "kube-controller-manager"
  },
  "spec": {
    "hostNetwork": true,
    "containers": [
      {
        "name": "kube-controller-manager",
        "image": "$HYPERKUBE_IMAGE",
        "command": [
          "/hyperkube",
          "controller-manager",
          "--address=0.0.0.0",
          $allocate_node_cidr_opts
          "--cluster-name=$(cluster_name)",
          "--cluster-signing-cert-file=/srv/kubernetes/ca.pem",
          "--cluster-signing-key-file=/srv/kubernetes/ca-key.pem",
          "--leader-elect=true",
          "--master=http://$(local_with_brackets):8080",
          "--root-ca-file=/srv/kubernetes/ca.pem",
          "--service-account-private-key-file=/srv/kubernetes/ca-key.pem",
          "--service-cluster-ip-range=$(service_cluster_ip_range)",
          "--v=2"
        ],
        "env": [
            {
                "name": "cluster_cidr",
                "value": "$cluster_cidr"
            },
            {
                "name": "cluster_name",
                "value": "$cluster_name"
            },
            {
                "name": "node_cidr_mask_size",
                "value": "$node_cidr_mask_size"
            },
            {
                "name": "local_with_brackets",
                "value": "$local_with_brackets"
            },
            {
                "name": "service_cluster_ip_range",
                "value": "$service_cluster_ip_range"
            }
        ],
        "volumeMounts": [
          {
            "name": "srvkube",
            "mountPath": "/srv/kubernetes",
            "readOnly": true
          },
          {
            "name": "etcssl",
            "mountPath": "/etc/ssl",
            "readOnly": true
          }
        ],
        "livenessProbe": {
          "httpGet": {
            "scheme": "HTTP",
            "host": "$local",
            "port": 10252,
            "path": "/healthz"
          },
          "initialDelaySeconds": 15,
          "timeoutSeconds": 15
        }
      }
    ],
    "volumes": [
      {
        "name": "srvkube",
        "hostPath": {
          "path": "/srv/kubernetes"
        }
      },
      {
        "name": "etcssl",
        "hostPath": {
          "path": "/etc/ssl"
        }
      }
    ]
  }
}
