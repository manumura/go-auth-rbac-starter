#!/bin/bash
current_date_time="$(date +%Y%m%d%H%M%S)";
echo "===== Building and pushing Docker image manumura/go-auth-rbac-starter:$current_date_time =====";
docker build -t manumura/go-auth-rbac-starter:$current_date_time .
docker push manumura/go-auth-rbac-starter:$current_date_time
echo "===== Docker image manumura/go-auth-rbac-starter:$current_date_time built and pushed successfully =====";

echo "===== Building and pushing Docker image manumura/go-auth-rbac-starter:latest =====";
docker build -t manumura/go-auth-rbac-starter:latest .
docker push manumura/go-auth-rbac-starter:latest
echo "===== Docker image manumura/go-auth-rbac-starter:latest built and pushed successfully =====";
