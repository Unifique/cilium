#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

etcd_version="v3.1.0"
k8s_version="v1.6.4"
HYPERKUBE_IMAGE=gcr.io/google_containers/hyperkube:${k8s_version}

certs_dir="${dir}/certs"
k8s_dir="${dir}/k8s"
cilium_dir="${dir}/cilium"

function get_options(){
    if [[ "${1}" == "ipv6" ]]; then
        cat <<'EOF' > "${dir}/env.bash"
# IPv6
controller_ip="fd01::b"
controller_ip_brackets="[${controller_ip}]"
local="::1"
local_with_brackets="[${local}]"
cluster_cidr="F00D::C0A8:0000:0:0/96"
cluster_dns_ip="FD03::A"
cluster_name="cilium-k8s-tests"
node_cidr_mask_size="112"
service_cluster_ip_range="FD03::/112"
allocate_node_cidr_opts=''
disable_ipv4=true
EOF
    else
        cat <<'EOF' > "${dir}/env.bash"
# IPv4
controller_ip="192.168.33.11"
controller_ip_brackets="${controller_ip}"
local="127.0.0.1"
local_with_brackets="${local}"
cluster_cidr="10.20.0.0/10"
cluster_dns_ip="172.20.0.10"
cluster_name="cilium-k8s-tests"
node_cidr_mask_size="16"
service_cluster_ip_range="172.20.0.0/16"
#allocate_node_cidr_opts='"--cluster-cidr=$(cluster_cidr)", \
#  "--allocate-node-cidrs=true", \
#  "--configure-cloud-routes=false", \
#  "--node-cidr-mask-size=$(node_cidr_mask_size)",'
disable_ipv4=false
EOF
    fi
    # Disable allocate node CIDR for both modes
    # since we don't know how to configure the
    # routes to reach the other node automatically.
    allocate_node_cidr_opts=''

    source "${dir}/env.bash"
}

function generate_certs(){
    bash "${certs_dir}/generate-certs.sh"
}

function install_cni(){
    sudo mkdir -p /opt/cni
    sudo mkdir -p /etc/cni/net.d

    sudo tee /etc/cni/net.d/10-cilium-cni.conf <<EOF
{
    "name": "cilium",
    "type": "cilium-cni",
    "mtu": 1450
}
EOF

    wget -nv https://storage.googleapis.com/kubernetes-release/network-plugins/cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz
    sudo tar -xvf cni-07a8a28637e97b22eb8dfe710eeae1344f69d16e.tar.gz -C /opt/cni
}

function install_etcd(){
    wget -nv https://github.com/coreos/etcd/releases/download/${etcd_version}/etcd-${etcd_version}-linux-amd64.tar.gz
    tar -xvf etcd-${etcd_version}-linux-amd64.tar.gz
    sudo mv etcd-${etcd_version}-linux-amd64/etcd* /usr/bin/
}

function install_kubectl(){
    wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubectl
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin
}

function install_kubelet(){
    wget -nv https://storage.googleapis.com/kubernetes-release/release/${k8s_version}/bin/linux/amd64/kubelet
    chmod +x kubelet
    sudo mv kubelet /usr/bin/
}

function create_pod_specs(){
    sed -e "s+\$HYPERKUBE_IMAGE+${HYPERKUBE_IMAGE}+g;\
        s+\$controller_ip_brackets+${controller_ip_brackets}+g;\
        s+\$controller_ip+${controller_ip}+g;\
        s+\$local+${local}+g;\
        s+\$service_cluster_ip+${service_cluster_ip_range}+g" \
    "${k8s_dir}/kube-api-server.json.sed" > "${k8s_dir}/kube-api-server.json"

    sed -e "s+\$HYPERKUBE_IMAGE+${HYPERKUBE_IMAGE}+g;\
        s+\$allocate_node_cidr_opts+${allocate_node_cidr_opts}+g;\
        s+\$cluster_cidr+${cluster_cidr}+g;\
        s+\$cluster_name+${cluster_name}+g;\
        s+\$local_with_brackets+${local_with_brackets}+g;\
        s+\$local+${local}+g;\
        s+\$node_cidr_mask_size+${node_cidr_mask_size}+g;\
        s+\$service_cluster_ip_range+${service_cluster_ip_range}+g" \
    "${k8s_dir}/kube-controller-manager.json.sed" > "${k8s_dir}/kube-controller-manager.json"

    sed -e "s+\$HYPERKUBE_IMAGE+${HYPERKUBE_IMAGE}+g;\
        s+\$local_with_brackets+${local_with_brackets}+g;\
        s+\$local+${local}+g" \
    "${k8s_dir}/kube-scheduler.json.sed" > "${k8s_dir}/kube-scheduler.json"
}

function install_k8s_master_config(){
    sudo mkdir -p /srv/kubernetes/
    sudo mkdir -p /etc/kubernetes/manifests/

    sudo cp "${certs_dir}/token.csv" \
            "${certs_dir}/ca.pem" \
            "${certs_dir}/ca-key.pem" \
            "${certs_dir}/kubernetes-key.pem" \
            "${certs_dir}/kubernetes.pem" \
            /srv/kubernetes/

    sudo cp "${k8s_dir}/kube-api-server.json" \
            "${k8s_dir}/kube-controller-manager.json" \
            "${k8s_dir}/kube-scheduler.json" \
            /etc/kubernetes/manifests/
}

function copy_etcd_certs(){
    sudo mkdir -p /etc/etcd/

    sudo cp "${certs_dir}/ca.pem" \
            "${certs_dir}/kubernetes-key.pem" \
            "${certs_dir}/kubernetes.pem" \
            /etc/etcd/
}

function generate_etcd_config(){
    sudo mkdir -p /var/lib/etcd

    sudo tee /etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/bin/etcd --name master \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --initial-advertise-peer-urls https://${controller_ip_brackets}:2380 \\
  --listen-peer-urls https://${controller_ip_brackets}:2380 \\
  --listen-client-urls https://${controller_ip_brackets}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls https://${controller_ip_brackets}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster master=https://${controller_ip_brackets}:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

function generate_kubelet_config(){
    BOOTSTRAP_TOKEN=$(cat ${certs_dir}/token.csv | cut -d"," -f1)

    kubectl config set-cluster ${cluster_name} \
        --certificate-authority=${certs_dir}/ca.pem \
        --embed-certs=true \
        --server=https://${controller_ip_brackets}:6443 \
        --kubeconfig=bootstrap.kubeconfig

    kubectl config set-credentials kubelet-bootstrap \
        --token=${BOOTSTRAP_TOKEN} \
        --kubeconfig=bootstrap.kubeconfig

    kubectl config set-context default \
        --cluster=${cluster_name} \
        --user=kubelet-bootstrap \
        --kubeconfig=bootstrap.kubeconfig

    kubectl config use-context default --kubeconfig=bootstrap.kubeconfig

    sudo mkdir -p /var/lib/kubelet/
    sudo mkdir -p /etc/kubernetes/manifests

    sudo cp "${certs_dir}/$(hostname).pem" \
            "${certs_dir}/$(hostname)-key.pem" \
        /var/lib/kubelet/

    sudo cp bootstrap.kubeconfig /var/lib/kubelet/kubeconfig

    sudo tee /etc/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
ExecStartPre=/bin/bash -c ' \\
        if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
           /bin/mount bpffs /sys/fs/bpf -t bpf; \\
        fi'
ExecStart=/usr/bin/kubelet \\
  --allow-privileged=true \\
  --cloud-provider= \\
  --cluster-dns=${cluster_dns_ip} \\
  --cluster-domain=${cluster_name}.local \\
  --container-runtime=docker \\
  --experimental-bootstrap-kubeconfig=/var/lib/kubelet/kubeconfig \\
  --make-iptables-util-chains=false \\
  --network-plugin=cni \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --pod-manifest-path=/etc/kubernetes/manifests/ \\
  --serialize-image-pulls=false \\
  --require-kubeconfig=true \\
  --register-node=true \\
  --cert-dir=/var/lib/kubelet \\
  --tls-cert-file=/var/lib/kubelet/$(hostname).pem \\
  --tls-private-key-file=/var/lib/kubelet/$(hostname)-key.pem \\
  --v=2

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

function generate_kubectl_config(){
    kubectl config set-cluster ${cluster_name} \
        --certificate-authority=${certs_dir}/ca.pem \
        --embed-certs=true \
        --server=https://${controller_ip_brackets}:6443

    kubectl config set-credentials admin \
        --embed-certs=true \
        --client-certificate=${certs_dir}/admin.pem \
        --client-key=${certs_dir}/admin-key.pem

    kubectl config set-context ${cluster_name} \
        --cluster=${cluster_name} \
        --user=admin

    kubectl config use-context ${cluster_name}
}

function install_cilium_config(){
    sudo mkdir -p /var/lib/cilium

    sudo cp "${certs_dir}/ca.pem" \
       "/var/lib/cilium/etcd-ca.pem"

    sudo tee /var/lib/cilium/etcd-config.yml <<EOF
---
endpoints:
- https://${controller_ip_brackets}:2379
ca-file: '/var/lib/cilium/etcd-ca.pem'
EOF

    kubectl config set-cluster ${cluster_name} \
        --certificate-authority=${certs_dir}/ca.pem \
        --embed-certs=true \
        --server=https://${controller_ip_brackets}:6443 \
        --kubeconfig=cilium.kubeconfig

    kubectl config set-credentials admin \
        --client-certificate=${certs_dir}/admin.pem \
        --client-key=${certs_dir}/admin-key.pem \
        --embed-certs=true \
        --kubeconfig=cilium.kubeconfig

    kubectl config set-context ${cluster_name} \
        --cluster=${cluster_name} \
        --user=admin \
        --kubeconfig=cilium.kubeconfig

    kubectl config use-context ${cluster_name} \
        --kubeconfig=cilium.kubeconfig

    sudo cp cilium.kubeconfig /var/lib/cilium/kubeconfig
}

function start_etcd(){
    sudo systemctl daemon-reload
    sudo systemctl enable etcd
    sudo systemctl start etcd
    sudo systemctl status etcd --no-pager
}

function start_kubelet(){
    sudo systemctl daemon-reload
    sudo systemctl enable kubelet
    sudo systemctl restart kubelet
    sudo systemctl status kubelet --no-pager
}

function add_kubelet_rbac(){
    kubectl create clusterrolebinding kubelet-bootstrap \
        --clusterrole=system:node \
        --user=kubelet-bootstrap
}

function clean_all(){
    sudo service kubelet stop
    sudo service etcd stop
    sudo docker rm -f `sudo docker ps -aq`
    sudo rm -fr /var/lib/etcd
    sudo rm -fr /etc/kubernetes/manifests
    sudo rm -fr /var/lib/kubelet
}

function fresh_install(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "ipv6")
              ipv6="ipv6"
            ;;
          esac
        ;;
      esac
    done

    get_options "${ipv6}"

    install_cni
    install_kubectl
    install_kubelet

    if [[ "$(hostname)" -eq "cilium-k8s-master" ]]; then
        install_etcd
        create_pod_specs
        install_k8s_master_config
        copy_etcd_certs
        generate_etcd_config
        start_etcd
    fi

    install_cilium_config
    generate_kubelet_config
    start_kubelet
    generate_kubectl_config

    #We only add kubelet RBAC permission on node-2 since
    #it gave more than enough time for cilium-k8s-master
    #to set up kube-apiserver
    if [[ "$(hostname)" -eq "cilium-k8s-node-2" ]]; then
        add_kubelet_rbac
    fi
}

function reinstall(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "yes-delete-all-etcd-data")
              clean_etcd=1
            ;;
            "ipv6")
              ipv6="ipv6"
            ;;
          esac
        ;;
      esac
    done

    get_options "${ipv6}"

    if [[ -n "${clean_etcd}" ]]; then
        clean_all
    fi

    if [[ "$(hostname)" -eq "cilium-k8s-master" ]]; then
        create_pod_specs
        install_k8s_master_config
        copy_etcd_certs
        generate_etcd_config
        start_etcd
    fi

    install_cilium_config
    generate_kubelet_config
    start_kubelet
    generate_kubectl_config

    #We only add kubelet RBAC permission on node-2 since
    #it gave more than enough time for cilium-k8s-master
    # to set up kube-apiserver
    if [[ "$(hostname)" -eq "cilium-k8s-node-2" ]]; then
        add_kubelet_rbac
    fi
}

function deploy_cilium(){
    while getopts ":-:" opt; do
      case $opt in
        "-")
          case "${OPTARG}" in
            "lb-mode")
              lb=1
            ;;
          esac
        ;;
      esac
    done
    
    source "${dir}/env.bash"

    rm "${cilium_dir}/cilium-lb-ds.yaml" \
       "${cilium_dir}/cilium-ds.yaml" \
       "${cilium_dir}/cilium-ds-1.yaml" \
       "${cilium_dir}/cilium-ds-2.yaml" \
        2>/dev/null

    if [[ -n "${lb}" ]]; then
        node_selector='"kubernetes.io/hostname": "cilium-k8s-master"'
        # In loadbalancer mode we set the snoop and LB interface to
        # enp0s8, the interface with IP 192.168.33.11.
        iface='enp0s8'

        sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
                s+\$node_selector+${node_selector}+g;\
                s+\$iface+${iface}+g" \
            "${cilium_dir}/cilium-lb-ds.yaml.sed" > "${cilium_dir}/cilium-lb-ds.yaml"

        node_selector='"kubernetes.io/hostname": "cilium-k8s-node-2"'
        node_address='#'
        ipv4_range='#'

        sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
                s+\$node_selector+${node_selector}+g;\
                s+\$node_address+${node_address}+g;\
                s+\$ipv4_range+${ipv4_range}+g;\
                s+\$server_number+1+g;\
                s+\$iface+${iface}+g" \
            "${cilium_dir}/cilium-ds.yaml.sed" > "${cilium_dir}/cilium-ds.yaml"
    else
        node_selector='"beta.kubernetes.io/arch": "amd64"'
        # In vxlan mode we set the snoop to "undefined"
        # so the default tunnel will be vxlan.
        iface='undefined'

        # FIX ME: Once we know how to get the node address
        # and set the routes automatically, remove this hack
        node_selector='"kubernetes.io/hostname": "cilium-k8s-master"'
        node_address='- "--node-address=F00D::C0A8:210B:0:0"'
        ipv4_range='- "--ipv4-range=10.11.0.1"'

        sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
                s+\$node_selector+${node_selector}+g;\
                s+\$node_address+${node_address}+g;\
                s+\$ipv4_range+${ipv4_range}+g;\
                s+\$server_number+1+g;\
                s+\$iface+${iface}+g" \
            "${cilium_dir}/cilium-ds.yaml.sed" > "${cilium_dir}/cilium-ds-1.yaml"

        node_selector='"kubernetes.io/hostname": "cilium-k8s-node-2"'
        node_address='- "--node-address=F00D::C0A8:210C:0:0"'
        ipv4_range='- "--ipv4-range=10.12.0.1"'

        sed -e "s+\$disable_ipv4+${disable_ipv4}+g;\
                s+\$node_selector+${node_selector}+g;\
                s+\$node_address+${node_address}+g;\
                s+\$ipv4_range+${ipv4_range}+g;\
                s+\$server_number+2+g;\
                s+\$iface+${iface}+g" \
            "${cilium_dir}/cilium-ds.yaml.sed" > "${cilium_dir}/cilium-ds-2.yaml"
    fi

    echo "dns_node_selector='${node_selector}'" >> "${dir}/env.bash"
    echo "lb='${lb}'" >> "${dir}/env.bash"

    kubectl create -f "${cilium_dir}"

    # Check if the output is md5sum("1 1") which means we have
    # cilium-ds-1 and cilium-ds-2 up and running.
    until [ "$(kubectl get ds --namespace kube-system | grep cilium | awk '{ print $4 }' | md5sum  )" = "f2160c8ffedf48068f2e1137e0a3a7e7  -" ]; do
	    echo "----- Waiting for Cilium to get into 'ready' state in ${cluster_name} cluster -----"
	    sleep 5
    done
}

case "$1" in
        generate_certs)
            generate_certs
            ;;
        fresh_install)
            shift
            fresh_install "$@"
            ;;
        reinstall)
            shift
            reinstall "$@"
            ;;
        deploy_cilium)
            shift
            deploy_cilium "$@"
            ;;
        *)
            echo $"Usage: $0 {generate_certs|fresh_install [--ipv6]|reinstall [--yes-delete-all-etcd-data] [--ipv6]|deploy_cilium [--lb-mode]}"
            exit 1
esac
