#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../helpers.bash"

source "${dir}/../cluster/env.bash"

kubedns_dir="${dir}/deployments/kubedns"

dns_svc_file="${kubedns_dir}/kubedns-svc.yaml"
dns_rc_file="${kubedns_dir}/kubedns-rc.yaml"
dns_sa_file="${kubedns_dir}/kubedns-sa.yaml"
dns_cm_file="${kubedns_dir}/kubedns-cm.yaml"

node_selector=${dns_node_selector:-'"kubernetes.io/hostname": "cilium-k8s-node-2"'}

sed "s/\$DNS_SERVER_IP/${cluster_dns_ip}/" "${dns_svc_file}.sed" > "${dns_svc_file}"

sed -e "s+\$DNS_DOMAIN+${cluster_name}+g;\
        s+\$NODE_SELECTOR+${node_selector}+g;\
        s+\$local_with_brackets+${local_with_brackets}+g;\
        s+\$local+${local}+g" \
    "${dns_rc_file}.sed" > "${dns_rc_file}"

kubectl create -f "${dns_sa_file}"

kubectl create -f "${dns_cm_file}"

kubectl create -f "${dns_svc_file}"

kubectl create -f "${dns_rc_file}"

until [ "$(kubectl get endpoints -n kube-system kube-dns | grep ":53")" ]; do
    echo "Waiting for kubedns service endpoints to be ready"
    sleep 2s
done
