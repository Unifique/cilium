{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "kube-apiserver"
  },
  "spec": {
    "hostNetwork": true,
    "containers": [
      {
        "name": "kube-apiserver",
        "image": "$HYPERKUBE_IMAGE",
        "command": [
          "/hyperkube",
          "apiserver",
          "--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota",
          "--advertise-address=$(controller_ip)",
          "--allow-privileged=true",
          "--apiserver-count=1",
          "--authorization-mode=RBAC",
          "--bind-address=0.0.0.0",
          "--client-ca-file=/srv/kubernetes/ca.pem",
          "--enable-swagger-ui=false",
          "--etcd-cafile=/srv/kubernetes/ca.pem",
          "--etcd-certfile=/srv/kubernetes/kubernetes.pem",
          "--etcd-keyfile=/srv/kubernetes/kubernetes-key.pem",
          "--etcd-servers=https://$(controller_ip_brackets):2379",
          "--experimental-bootstrap-token-auth",
          "--insecure-bind-address=0.0.0.0",
          "--kubelet-certificate-authority=/srv/kubernetes/ca.pem",
          "--kubelet-client-certificate=/srv/kubernetes/kubernetes.pem",
          "--kubelet-client-key=/srv/kubernetes/kubernetes-key.pem",
          "--kubelet-https=true",
          "--runtime-config=rbac.authorization.k8s.io/v1alpha1",
          "--service-account-key-file=/srv/kubernetes/ca-key.pem",
          "--service-cluster-ip-range=$(service_cluster_ip)",
          "--service-node-port-range=30000-32767",
          "--tls-cert-file=/srv/kubernetes/kubernetes.pem",
          "--tls-private-key-file=/srv/kubernetes/kubernetes-key.pem",
          "--token-auth-file=/srv/kubernetes/token.csv",
          "--v=2"
        ],
        "env": [
            {
                "name": "controller_ip",
                "value": "$controller_ip"
            },
            {
                "name": "controller_ip_brackets",
                "value": "$controller_ip_brackets"
            },
            {
                "name": "service_cluster_ip",
                "value": "$service_cluster_ip"
            }
        ],
        "ports": [
          {
            "name": "https",
            "hostPort": 443,
            "containerPort": 443
          },
          {
            "name": "local",
            "hostPort": 8080,
            "containerPort": 8080
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
            "port": 8080,
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
