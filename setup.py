from setuptools import setup

__version__ = "1.0.0"

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name='aroma',
    version=__version__,
    description='an asyncio Mastodon API client',
    long_description_content_type='text/markdown',
    long_description=long_description,
    packages=['aroma'],
    install_requires=[
        'httpx',
        'websockets',
        'python-dateutil',
        'orjson'
    ],
    url='https://github.com/web3chan/aroma',
    author='zhoreeq',
    author_email='zhoreeq@protonmail.com',
    keywords='Mastodon API asyncio',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Communications',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
    ]
)
