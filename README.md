# : Identify Field Hierarchy of Programs's Input by Dynamic Data Flow Tracking

The purpose of this tool is to identify the field hierarchy of any binary program input.
These code is modified from [libdft64](https://github.com/AngoraFuzzer/libdft64).

## Differences with libdft64
- Only consider the mov type instruction as taint propagation.
- Replace the BDDTag in libdft64 by SegTag which is hierarchical.


## Build 

- Download Intel Pin 3.x and set PIN_ROOT to Pin's directory.

```sh
PREFIX=/path-to-install ./install_pin.sh
```
- build libdft64
```
make
```


### Usage
```shell
pin -t obj-intel64/track.so -- obj-intel64/mini_test.exe  cur_input
```

#### Arguments processed by Pin
  * `-follow_execv`: Instructs Pin to also instrument all processes spawned
     using the `exec(3)` class system calls by the program.
  * `-t`: Specifies the Pin tool to be used.
