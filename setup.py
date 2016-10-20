from setuptools import setup, find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
NEWS = open(os.path.join(here, 'NEWS.txt')).read()


version = '1.0'

install_requires = [
    # List your project dependencies here.
    # For more details, see:
    # http://packages.python.org/distribute/setuptools.html#declaring-dependencies
    'ReviewBoard==2.5.6.1',
]


setup(name='reviewboard-bitkeeper-scm',
    version=version,
    description="Support for BitKeeper repositories in ReviewBoard",
    long_description=README + '\n\n' + NEWS,

    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Framework :: Django :: 1.6",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Topic :: Software Development :: Version Control"
    ],
    keywords='reviewboard bitkeeper scm',
    author='Keir Robinson',
    author_email='keir.robinson@hds.com',
    url='https://github.com/mrkeir/reviewboard-bitkeeper-scm',
    license='MIT License',
    packages=find_packages('src'),
    package_dir = {'': 'src'},include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    entry_points={
        'reviewboard.scmtools': [
            'bk = rb_bitkeeper_scm.bk:BkTool',
        ]

    }
)
