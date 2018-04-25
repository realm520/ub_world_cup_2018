#!/bin/bash
export production=True
celery -A app:celery worker -l info -f ./%I.log -B --detach
