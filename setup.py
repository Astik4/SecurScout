from setuptools import setup, find_namespace_packages

setup(
    name="securscout",
    version="1.0.0",
    packages=find_namespace_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "jinja2",
        "flask"
    ],
    entry_points={
        "console_scripts": [
            "securscout=SecurScout.main:main",
        ],
    },
)
