from os.path import dirname, basename, isfile
import glob

modules = glob.glob(os.path.dirname(os.path.abspath(__file__)) + os.sep + "*.py")
command_module_collection = [ basename(f)[:-3] for f in modules if isfile(f) and not f.endswith('__init__.py') and not f.endswith('lenovo_utils.py') and not f.endswith('manage_inventory.py')]
__all__ = [ basename(f)[:-3] for f in modules if isfile(f) and not f.endswith('__init__.py')]