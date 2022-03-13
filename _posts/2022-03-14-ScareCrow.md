---
title: Bypassing AV using ScareCrow
layout: post
---

This post demonstrates how to bypass defender in order to execute your Cobalt Strike payload.

### Sources
https://github.com/optiv/ScareCrow
https://github.com/RCStep/CSSG


## Installing ScareCrow

First clone the git repository

![img1](https://imgur.com/sjvDX3e.png)

In order to build ScareCrow, you must have `Go` installed along with the following dependencies.

  ```
sudo apt install golang openssl osslsigncode mingw-w64
  ```

Once installed, build ScareCrow.

![build](https://imgur.com/MKCK0Xj.png)



## Installing CSSG

For the next part, we must install the Cobalt Strike Shellcode Generator

```
sudo apt install python2.7 python3.9
python -m pip install pycryptodome
python3 -m pip install pycryptodome
py -3 -m pip install pycryptodome
py -2 -m pip install pycryptodome
```

Download [CSSG](https://github.com/RCStep/CSSG) and move it to somewhere accessible.

Open the script manager by clicking "Cobalt Strike" in the top left of the client then selecting "Script Manager".

Press "Load" and open "CSSG_load.cna" as shown

![load](https://imgur.com/yIHwdhc.png)

We now need to create a listener in order to generate the shellcode to call back to it.
Press the headphones icon and setup your listener as needed.

![listener](https://imgur.com/7GCE9xd.png)

Once loaded, a new option should be added to the top menu, called "Shellcode".

![shellcode](https://imgur.com/LEY6tiS.png)

Open the Shellcode GUI and generate your payload, encryption such as XOR/AES is optional

![gen](https://imgur.com/zveOFuW.png)



## Using ScareCrow to generate the payload

Once you have made your shellcode, we can now use ScareCrow.

`./ScareCrow -I /path/to/shellcode -sandbox -noetw -domain www.ubuntu.com`

This command will convert our Cobalt Strike shellcode into an executable, with a fake certificate signed by "ubuntu.com", howver you can use `-vaid` to provide a valid code signing certificate.

The sandbox flag enables sandbox evasion by using `IsDomainJoined` calls, and the noetw flag disbaled ETW patching which prevents ETW events for being generated

https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing

![scarecrow](https://imgur.com/zmiuFGb.png)
