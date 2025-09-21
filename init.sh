#!/bin/sh

# Only copy if volume is empty
if [ -z "$(ls -A /data 2>/dev/null)" ]; then
    echo "Populating volume from image..."
    cp -r /opt/trivy-cache/. /data/trivy-cache/
    rm -rf /opt/trivy-cache
else
    echo "Volume already has data, skipping..."
fi

# Execute the container's CMD
exec "$@"
