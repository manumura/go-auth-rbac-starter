#!/bin/bash
docker run --env-file .env -p 9002:9002 manumura/go-auth-rbac-starter:latest
