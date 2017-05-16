# CTRAesEngine
C# Library to simulate the 3DS's hardware AES engine.

Acquire a copy of the 3ds's protected ARM9 bootrom, build, then include in a C# project.

To use:
```C#
using CTR;

// ...

var engine = new AesEngine();
// Optionally, load console unique keys as follows:
engine.SetOTP(my_encrypted_otp);
```

**Credits:**

[Steveice10](https://github.com/Steveice10): Unit Tests use a zero-key encrypted build of [FBI](https://github.com/Steveice10/FBI).

**Licensing:**

This software is licensed under the terms of the GPLv3.  
You can find a copy of the license in the LICENSE file.
