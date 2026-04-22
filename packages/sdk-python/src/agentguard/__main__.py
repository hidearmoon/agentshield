"""Allow running as `python -m agentguard`."""

from agentguard.cli import main
import sys

sys.exit(main())
