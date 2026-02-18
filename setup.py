from setuptools import find_packages, setup

from strongarm import __url__, __version__

setup(
    name="strongarm-ios",
    version=__version__,
    description="Mach-O/ARM64 analyzer",
    author="Data Theorem",
    url=__url__,
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "capstone>=5.0.1,<6",
        "more_itertools",
    ],
    extras_require={
        "dataflow": ["strongarm_dataflow==3.0.0"],
    },
    package_data={"strongarm": ["py.typed"]},
    data_files=[("", ["LICENSE.txt"])],
)
