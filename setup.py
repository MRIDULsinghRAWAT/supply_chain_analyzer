from setuptools import setup, find_packages

setup(
    name='supply-chain-analyzer',
    version='1.1.0',
    packages=find_packages(),
    install_requires=[
        'python-Levenshtein==0.25.1',
        'colorama==0.4.6',
        'requests==2.31.0',
        'packaging==23.2'
    ],
    entry_points={
        'console_scripts': [
            'scan-deps=analyzer.main:main',
        ],
    },
)