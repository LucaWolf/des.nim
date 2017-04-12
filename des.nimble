# Package

version       = "0.0.3"
author        = "LucaWolf <LucaWolf@users.noreply.github.com>"
description   = "3DES native library for Nim"
license       = "MIT"

skipDirs = @["tests"]
bin = @["tests/des_test"]

# Dependencies

requires "nim >= 0.16.0"

