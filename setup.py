from setuptools import setup, find_packages

setup(
    name="Profil3r",
    version="1.1.0",
    packages=find_packages(),
    author="Rog3rSm1th",
    author_email="r0g3r5@protonmail.com",
    install_requires=["requests>=2.28", "pwnedpasswords"],
    python_requires=">=3.9",
    description="Public profile OSINT discovery tool",
    include_package_data=True,
    url="https://github.com/coreylad/Profil3r",
    entry_points={"console_scripts": ["profil3r=profil3r.__main__:main"]},
    license="MIT",
)
