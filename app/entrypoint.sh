#!/bin/sh
set -e

# Only seed the logs once (so restarts don't duplicate the story).
if [ ! -f /opt/admin/logs/access.log ]; then
  /usr/local/bin/generate-logs.sh
fi

exec node server.js
