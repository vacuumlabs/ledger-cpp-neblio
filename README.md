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

Uncomment and comment the functions in `main` as you wish.

Run:

```
./main
```

The output for `getPublicKey` with our dev Ledger should be:

```
Opening Ledger connection
Getting public key - please confirm action on Ledger
Raw result data: 04 a3 82 4d 53 14 3b 63 82 f1 8e 85 b8 ce 64 98 48 92 9a a6 03 36 6b 8e 3e e6 c2 15 30 25 6d 1d a4 5e 17 71 86 0a e3 b3 a4 af 44 75 78 a4 d3 18 b9 5c 3d 70 ad d8 21 e5 fb 3a fd e4 11 6c d8 34 7d 22 4e 56 50 4a 78 51 68 33 65 38 67 63 58 38 72 34 50 75 52 46 46 77 71 67 6d 36 57 37 67 54 65 62 43 74 5c 7a 1d 1a f8 2c e6 40 6e ca 0b d4 d1 89 8b 1d a2 40 a8 ab 0b 50 0d 95 bb a3 94 e7 0d 6b be b2
Public key: 04 a3 82 4d 53 14 3b 63 82 f1 8e 85 b8 ce 64 98 48 92 9a a6 03 36 6b 8e 3e e6 c2 15 30 25 6d 1d a4 5e 17 71 86 0a e3 b3 a4 af 44 75 78 a4 d3 18 b9 5c 3d 70 ad d8 21 e5 fb 3a fd e4 11 6c d8 34 7d
Address: NVPJxQh3e8gcX8r4PuRFFwqgm6W7gTebCt
Chain code: 5c 7a 1d 1a f8 2c e6 40 6e ca 0b d4 d1 89 8b 1d a2 40 a8 ab 0b 50 0d 95 bb a3 94 e7 0d 6b be b2
```

For other sample outputs see [Expected APDUs and Results.md](<doc/Expected APDUs and Results.md>).

## Debug

Debugging in VS Code should work via CMake Tools extension. Just pressing `CTRL+F5` should work.
