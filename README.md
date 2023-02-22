# Ledger CPP playground for Nebl.io integration

## Setup

In addition to the steps mentioned, [the Neblio Ledger app](https://github.com/NeblioTeam/app-neblio) should also be loaded on your Ledger.

### Install dependencies

_NOTE: presumably only one of `libudev-dev` and `libusb-1.0-0-dev` is needed but I'm not sure which one, so just install both. Sorry._

```
sudo apt install libudev-dev libusb-1.0-0-dev libhidapi-dev
```

### Add hidapi to CMake

This can mostly be done by following instructions [on their github](https://github.com/libusb/hidapi/blob/master/BUILD.cmake.md) i.e. clone the repo and execute the following

```jsx
# precondition: create a <build dir> somewhere on the filesystem (preferably outside of the HIDAPI source)
# this is the place where all intermediate/build files are going to be located
cd <build dir>
# configure the build
cmake <HIDAPI source dir>
# build it!
cmake --build .
# install library; by default installs into /usr/local/
cmake --build . --target install
# NOTE: you need to run install command as root, to be able to install into /usr/local/
```

## Build and run

Generate CMake files:

```
cmake .
```

Build:

```
make
```

Run:

```
./main
```
