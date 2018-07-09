from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='cloudgenix_vff_push_config',
      version='1.1.1',
      description='Virtual Form Factor Config Push for CloudGenix',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/vff_push_config',
      author='Aaron Edwards',
      author_email='cloudgenix_vff_push_config@ebob9.com',
      license='MIT',
      install_requires=[
            'pyserial >= 3.0',
            'pexpect >= 4.0'
      ],
      packages=['cloudgenix_vff_push_config'],
      entry_points = {
            'console_scripts': [
                  'vff_push_config = cloudgenix_vff_push_config:go',
                  ]
      },
      classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3"
      ]
      )
