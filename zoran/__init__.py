#
from os import path

MODULE_PATH = path.join(path.abspath(path.dirname(__file__)), 'modules')
RESOURCE_PATH = path.abspath(path.join(path.dirname(__file__),
                                       'resources', ''))
TEMPLATE_PATH = path.join(path.abspath(path.dirname(__file__)),
                          'data', 'templates')
