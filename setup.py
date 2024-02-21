import setuptools 

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lpsn",
    version="1.0.0",
    description="LPSN-API - Programmatic Access to LPSN",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Julia Koblitz",
    author_email="julia.koblitz@dsmz.de",
    url='https://lpsn.dsmz.de/',
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Bio-Informatics",
    ],
    keywords="microbiology taxonomy nomenclature bacteria archaea",
    install_requires=[
        "python-keycloak",
        "requests>=2.25.1",
        "urllib3>=1.26.5"
    ]
)
