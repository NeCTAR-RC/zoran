from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='zoran',
      version=version,
      description="",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Russell Sim',
      author_email='russell.sim@gmail.com',
      url='',
      license='Apache2',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
          'Jinja2',
          'argparse',
          'lxml',
          'oslo_config',
          'pymongo',
          'python-dateutil',
          'python-novaclient',
          'pytz',
          'xmltodict',
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
