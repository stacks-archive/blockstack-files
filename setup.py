#!/usr/bin/python

from setuptools import setup, find_packages

# to set __version__
exec(open('blockstack_file/version.py').read())

setup(
    name='blockstack-file',
    version=__version__,
    url='https://github.com/blockstack/blockstack-file',
    license='GPLv3',
    author='Blockstack.org',
    author_email='support@blockstack.org',
    description='Blockstack encrypted file sharing',
    keywords='blockchain git crypography name key value store data',
    packages=find_packages(),
    download_url='https://github.com/blockstack/blockstack-file/archive/master.zip',
    zip_safe=False,
    include_package_data=True,
    scripts=['bin/blockstack-file'],
    install_requires=[
        'blockstack-client>=0.0.13.0',
        'blockstack-gpg>=0.0.1.0'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
