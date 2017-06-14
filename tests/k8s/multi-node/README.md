## Kubernetes multi node tests

This directory contains the necessary files to setup a 2 node kubernetes
cluster.

The directory structure is composed as follow:

- `cluster/` - files that have the kubernetes configurations
    - `certs/` - certificates used in kubernetes components and in etcd, the
    files are already generated so there's no need to regenerated them again.
    - `cilium/` - cilium daemon sets adjusted to this cluster with a daemon set
    for the loadbalancer mode. The files are generated on the fly based on the
    `*.sed` files present.
    - `k8s/` - api-server, controller-manager and scheduler for the kubernetes
    master. The files are generated on the fly depending on the IP version
    chosen and if loadbalancer mode is set or not.
    - `cluster-manager.bash` - the script in charge of the certificates,
    kubernetes and cilium files generation. It is also in charge on setting up
    and deploy a fully kubernetes cluster with etcd running. On this file is
    possible to change a couple options, such as etcd version and k8s version
    among others.
- `tests/` - the directory where the tests should be stored
    - `deployments/` - yaml files to be managed for each runtime tests.
    - `ipv4/` - tests that are designed to be ran only in IPv4 mode.
    - `ipv6/` - tests that are designed to be ran only in IPv6 mode.
    - `00-setup-kubedns.sh` - kubedns scripts that will setup kubernetes
    depending on which IP version is being used in the kubernetes cluster
    deployed.
    - `xx-test-name.sh` - all tests with this format will be ran in both IPv4
    and IPv6 mode.
- `run-tests.bash` - script that is in charge of running the runtime tests, to
set up the cluster for the IPv6 environment and to run the runtime tests in
IPv6.

### Cluster architecture

When running `vagrant up` there will be 2 VMs, `cilium-k8s-master` and
`cilium-k8s-node-2`.

#### `cilium-k8s-master`

`cilium-k8s-master` will contain the etcd server, kube-apiserver,
kube-controller-manager, kube-scheduler and a kubelet instance running.

All components will be running in containers **except** kubelet and etcd.

This node will have the 3 static IPs and 2 interfaces:

`enp0s8`: `192.168.33.11/24` and `fd01::b/16`

`enp0s9`: `192.168.34.11/24`

#### `cilium-k8s-node-2`

`cilium-k8s-node-2` will only container a kubelet instance running.

This node will also have the 3 static IPs and 2 interfaces:

`enp0s8`: `192.168.33.12/24` and `fd01::c/16`

`enp0s9`: `192.168.34.12/24`

### Switching between IPv4 and IPv6

After running `vagrant up` kubernetes and etcd will be running with TLS set up.
Note that cilium and kubedns **will not be set up**.

Kubernetes will be running in IPv4 mode by default, to run on IPv6 mode, after
the machines are set up and running, run:

```
vagrant ssh ${vm} -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/cluster/cluster-manager.bash reinstall --ipv6 --yes-delete-all-etcd-data'
vagrant ssh ${vm} -- -t 'sudo cp -R /root/.kube /home/vagrant'
vagrant ssh ${vm} -- -t 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
```

Where `${vm}` should be replaced with `cilium-k8s-master` and
`cilium-k8s-node-2`.

This will reset the kubernetes cluster to it's initial state.

To revert it back to IPv4, run the same commands before without the `--ipv6`
option on the first command.

### Deploying cilium

To deploy cilium after kubernetes is set up, simply run:

```
vagrant ssh cilium-k8s-node-2 -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/cluster/cluster-manager.bash deploy_cilium'
```

There only need to run the command in `cilium-k8s-node` as kubernetes daemon set
will be deployed on each node accordingly.

Cilium will also be connecting to etcd and kubernetes using TLS.

#### Loadbalancer mode (kubernetes ingress)

In loadbalancer mode, the `cilium-k8s-master` will run a daemon set for designed
for this purpose, with `--lb` and `--snoop-device` set to `enp0s8`.
