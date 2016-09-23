#!/bin/bash
set -ev

if python -c "import sys; import os; sys.exit(sys.version_info >= (3,5) and os.environ.get('EVENT_LOOP') == 'uvloop')"; then
    pip install uvloop;
fi

exit 0;
