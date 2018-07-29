from setuptools import setup, find_packages

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

def get_requirements():

    fname = "requirements.txt"
    with open(fname) as f:
        content = f.readlines()
    c = []
    for x in content:
        # Strip out white space
        l = x.strip()
        # Skip Empty
        if not l:
            continue
        # Ignore comment lines
        if '#' in l:
            continue

        c.append(l)
    return c


setup(name='juniper-vpn',
      # Follow https://packaging.python.org/tutorials/distributing-packages/#id59
      # Date based versioning
      version='2018.7',
      description='Juniper VPN wrapper for openconnect',

      classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 3 - Alpha',

          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
      ],

      keywords='automation vpn',

      url='https://github.com/russdill/juniper-vpn-py',
      author='Russ Dill',
      author_email='Russ.Dill@gmail.com',

      license='License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',

      packages=find_packages(exclude=['contrib', 'docs', 'tests']),

      install_requires=get_requirements(),

      scripts=['juniper-vpn.py', 'tncc.py'],

      # Does'nt really work atm..
      # https://github.com/pypa/setuptools/issues/460
      data_files=[('sample.cfg', ['cfg/sample.cfg']),
                  ('README.authenticator', ['doc/README.authenticator']),
                  ('README.host_checker', ['doc/README.host_checker'])],

      include_package_data=True,
      zip_safe=False)

# Format via !autopep8 -i -a %
# vim: et:ts=4
