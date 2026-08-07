#!/bin/sh

#kubectl create secret generic litestream --from-file=litestream.yaml --save-config --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deploy kustomize-casanostr
