#!/bin/bash
set -ev

if python -c "import sys; import os; sys.exit(sys.version_info >= (3,5) or os.environ.get('EVENT_LOOP') == 'asyncio')"; then
    py.test --cov-config .coveragerc --cov=saltyrtc --loop=$EVENT_LOOP;
fi

exit 0;
