import sys
import os

# A hack to import the other files without placing the files in the modules directory.
dirname = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, dirname)

from pt_gdb import PageTableDumpGdbFrontend

PageTableDumpGdbFrontend()
