from setuptools import setup, find_packages
setup(name='adwsdomaindump',
      version='0.11.0',
      description='Active Directory information dumper via ADWS',
      author='mverschu',
      author_email='',
      url='https://github.com/dirkjanm/ldapdomaindump/',
      packages=find_packages(),
      requires_python=">=3.6",
      install_requires=['dnspython', 'impacket>=0.11.0', 'pycryptodomex'],
      package_data={'adwsdomaindump': ['style.css']},
      include_package_data=True,
      entry_points= {
        'console_scripts': ['adwsdomaindump=adwsdomaindump:main']
      },
      license="MIT",
      )
