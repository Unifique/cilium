{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "kube-scheduler"
  },
  "spec": {
    "hostNetwork": true,
    "containers": [
      {
        "name": "kube-scheduler",
        "image": "$HYPERKUBE_IMAGE",
        "command": [
          "/hyperkube",
          "scheduler",
          "--master=$(local_with_brackets):8080"
        ],
        "env": [
            {
                "name": "local_with_brackets",
                "value": "$local_with_brackets"
            }
        ],
        "livenessProbe": {
          "httpGet": {
            "scheme": "HTTP",
            "host": "$local",
            "port": 10251,
            "path": "/healthz"
          },
          "initialDelaySeconds": 15,
          "timeoutSeconds": 15
        }
      }
    ]
  }
}
