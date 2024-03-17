import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ReverserAI",
    version="1.0",
    author="Tim Blazytko",
    author_email="tim@blazytko.to",
    description="Provides automated reverse engineering assistance through the use of local large language models (LLMs) on consumer hardware.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mrphrazer/reverser_ai",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: POSIX :: Linux",
    ],
    packages=setuptools.find_packages(),
    python_requires='>=3.10',
)
