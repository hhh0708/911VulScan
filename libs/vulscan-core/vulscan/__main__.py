"""Allow running `python -m vulscan`."""
from vulscan.cli import main
import sys

sys.exit(main())
