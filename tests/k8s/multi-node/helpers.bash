#!/usr/bin/env bash

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                          K8s Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

    cilium_id=$(docker ps -aq --filter=name=cilium-agent)
	echo "------------------------------------------------------------------------"
	echo "                            Cilium logs"
    docker logs ${cilium_id}
	echo ""
	echo "------------------------------------------------------------------------"

	exit 1
}
