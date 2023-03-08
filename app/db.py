import sys
import sqlite3
from pathlib import Path

sys.path.append(str(Path(sys.argv[0]).absolute().parent.parent))
from . import var