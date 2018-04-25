#!/bin/bash
# export production=True
mkdir -p logs
celery -A app:celery worker -l info --concurrency=4 -f ./logs/%I.log -B --detach
