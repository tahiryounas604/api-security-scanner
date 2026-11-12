"""Entry point: python -m api_security_scanner"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
