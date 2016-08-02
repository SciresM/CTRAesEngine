# CTRAesEngine
C# Library to simulate the 3DS's hardware AES engine.

Edit the hardcoded keys to your liking, build, then include in a C# project.

Alternatively, wait for public dumps of the 3DS's bootrom to appear and for me to implement loading keys from it.

To use:
```C#
using CTR;

// ...

var engine = new AesEngine();
```

**Credits:**

[Steveice10](https://github.com/Steveice10): Unit Tests use a zero-key encrypted build of [FBI](https://github.com/Steveice10/FBI).

**Licensing:**

This software is licensed under the terms of the GPLv3.  
You can find a copy of the license in the LICENSE file.
