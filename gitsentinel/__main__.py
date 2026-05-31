"""Allow running GitSentinel as a module: python -m gitsentinel"""

import sys
from gitsentinel.main import main

sys.exit(main())
