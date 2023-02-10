# DISSInput: Identify fields and their hierarchy of programs's input by Dynamic Data Flow Tracking 

The purpose of this tool is to identify the field hierarchy of any binary program input.
These code is modified from [libdft64](https://github.com/AngoraFuzzer/libdft64).

## Modifications based on libdft64

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
cd tools
pin -t obj-intel64/dissinput.so -input_file cur_input -- obj-intel64/mini_test.exe  cur_input
```

This step outputs two files 

1. ***input_tree.json***    This file is the tree of the input(Have removed the redundant nodes).

```
{
    "begin": 0,
    "end": 0,
    "children": [
        {
            "begin": 0,
            "end": 1764,
            "children": [
                {
                    "begin": 1699,
                    "end": 1764,
                    "children": [
                        {
                            "begin": 1753,
                            "end": 1762,
                            "children": []
                        },
                        {
                            "begin": 1747,
                            "end": 1750,
                            "children": []
                        },
                        {
                            "begin": 1743,
                            "end": 1745,
                            "children": []
                        }
                    ]
                }
            ]
        }
    ]
}
```

**More usage for this file see** [M4nval/DISSInput-tmin (github.com)](https://github.com/M4nval/DISSInput-tmin).

2. ***tagList.out***   This file contains all the origin taint tag in program running. 

```
{"id":1, "begin":0, "end":50, "parent":0, "temp":0}
{"id":2, "begin":0, "end":20, "parent":1, "temp":0}
{"id":3, "begin":0, "end":20, "parent":1, "temp":0}
{"id":4, "begin":20, "end":25, "parent":1, "temp":0}
{"id":5, "begin":25, "end":30, "parent":1, "temp":0}
{"id":6, "begin":30, "end":40, "parent":1, "temp":0}
{"id":7, "begin":30, "end":35, "parent":6, "temp":0}
{"id":8, "begin":35, "end":40, "parent":6, "temp":0}
{"id":9, "begin":35, "end":40, "parent":6, "temp":0}
{"id":10, "begin":30, "end":40, "parent":1, "temp":0}
{"id":11, "begin":30, "end":40, "parent":1, "temp":0}
{"id":12, "begin":30, "end":50, "parent":0, "temp":0}
{"id":13, "begin":40, "end":50, "parent":1, "temp":0}
……
```

In addition, "result_analysis.py" is a tool for visualizing the "tagList.out":

```shell
pip install pyecharts
python result_analysis.py
```

This step draw the picture about the input struct by tagList.out generate by prev step.
The output is a file named "result.html".(see the following drawing)
![image](https://user-images.githubusercontent.com/13733408/217983827-faf238d2-2150-407f-9ff8-f9712f883888.png)



#### Arguments processed by Pin
  * `-follow_execv`: Instructs Pin to also instrument all processes spawned
     using the `exec(3)` class system calls by the program.
  * `-t`: Specifies the Pin tool to be used.
