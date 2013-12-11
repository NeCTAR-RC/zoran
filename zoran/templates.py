import jinja2

from zoran import TEMPLATE_PATH


TEMPLATE_LOADER = jinja2.FileSystemLoader(searchpath=TEMPLATE_PATH)
TEMPLATE_ENV = jinja2.Environment(loader=TEMPLATE_LOADER)
