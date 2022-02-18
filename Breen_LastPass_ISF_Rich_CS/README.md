# Volatility Plugin Competition 2021

This is a single document covering multiple submissions. 

- Symbol Generator & Public ISF Server
- Cobalt Strike Plugin
- Rich Header Plugin


## Symbol Generator & Public ISF Server

https://isf-server.techanarchy.net/

This is a simple frontend to a pool of growing pre-generated Linux Symbol files. You can search by Kernel String `uname -r` or you can search for the banner as found by `banners.Banners`

This collection is designed to reduce the amount of time an analyst requires to start an investigation, as they will not need to set up an environment to create their own Symbol File they can simple search, download and use it immediatly. 

This server also supports the 'REMOTE_ISF_URL' with a banners.json file https://volatility3-symbols.s3.eu-west-1.amazonaws.com/banners.json

### Motivation

Time is an important factor when performing Incident Response during a live incident. Memory forensics can yeild quick results, however for Linux images there is a technical hurdle to acquire a compatible Symbol file before analysis can begin. This project started as a means to reduce this time and remove or reduce the technical hurdle. 


Volatility3 has moved away from Profiles to Symbol tables and is not backward compatible with the old profiles. When investigating a Linux memory image you must first generate an ISF file that matches the running kernel. If this has not already been done the analyst must create this. 

The creation of the symbol file is a technical process and the current method in place is to install the debug symbols and use the dwarf2json tool to create the ISF Json file. 

This can be technially challenging in some situations especially if you no longer have access to the host or an identical installation. 

Alternativly it is possible to extract the reqiured files from known packages and process them in this way, although this can be performed offline the process and tooling to perform this is still not fully matured and can require additioanl steps that can be time consuming 

### Source Code
There are two components. 

The Symbol Generator, an extensible framework that can be used to process single kernels or all availiable. 
This is a last minute addition to my submission so its sill being written but the core functionality with support for Ubuntu (Main, AWS, Azure and GCP Varients), Debian (Main, AWS) included. 

The source for this component can be found at https://github.com/kevthehermit/volatility_symbols

The Symbol Server, This uses AWS and DynamoDB for a serverless setup I plan to release the source for this so so teams can run their own. But this is a future project.
For the time being i am keeping the source for this specific component closed until I can make a "local" version.

### Usage

```
usage: symbol_maker.py [-h] -d {ubuntu,debian} -k KERNEL [-b BRANCH] [-v]

Generate a volatilty symbol file for a given distro and kernel version

optional arguments:
  -h, --help            show this help message and exit
  -d {ubuntu,debian}, --distro {ubuntu,debian}
                        Target Distribution
  -k KERNEL, --kernel KERNEL
                        Target Kernel release or 'all' The output of `uname -r`
  -b BRANCH, --branch BRANCH
                        Target Kernel branch e.g. linux-aws
  -v, --verbose         Verbose Debug logging
```


### Examples

To generate a symbol file for `Debian` `4.9.0-13-amd64` use the following command

`python3 symbol_maker.py -d debian -k '4.9.0-13-amd64'`

To generate a symbol file for `Ubuntu` `5.11.0-43-generic` use the following command 

`python3 symbol_maker.py -d ubuntu -k '5.11.0-43-generic' `

To generate a symbol file for `AWS` `Ubuntu` `4.15.0-1048-aws` use the following command

`python3 symbol_maker.py -d ubuntu -b 'linux-aws' -k '4.15.0-1048-aws'`

### Future

I continue to write the parsers for major OS versions, Fedora and Centos are next. For each supported Distribution i will continue to push Symobl Files to the AWS instance. I also have a set of workers that will monitor for new releases and push symbol files as they become availiable. 


## CobaltStrike Beacon Parser

This plugin will scan all process in active memory for signs of a Cobalt Strike Configuration block, if found it will attempt to parse and extract relevant information.

### Source Code

The latest version of the source code can be found at https://github.com/Immersive-Labs-Sec/volatility_plugins/tree/main/cobaltstrike


### Usage

Scan and output in to JSON format

`vol -r json -f Server16-CobaltStrike.raw -p ./volatility_plugins/ cobaltstrike`

```
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
[
  {
    "Jitter": 0,
    "License ID": xxxxxxxxxx,
    "PID": 4396,
    "POST_PATH": "",
    "Pipe": "\\\\.\\pipe\\msagent_89",
    "Port": 4444,
    "Process": "ShellExperienc",
    "Server": "",
    "Sleep": 10000,
    "__children": [],
    "x64 Install_Path": "%windir%\\sysnative\\rundll32.exe",
    "x86 Install_Path": "%windir%\\syswow64\\rundll32.exe"
  },
  {
    "Jitter": 0,
    "License ID": xxxxxxxxxx,
    "PID": 4396,
    "POST_PATH": "",
    "Pipe": "\\\\.\\pipe\\msagent_89",
    "Port": 4444,
    "Process": "ShellExperienc",
    "Server": "",
    "Sleep": 10000,
    "__children": [],
    "x64 Install_Path": "%windir%\\sysnative\\rundll32.exe",
    "x86 Install_Path": "%windir%\\syswow64\\rundll32.exe"
  }
]
```

Scan and output in table format

`vol -r pretty -f Server16-CobaltStrike.raw -p ./volatility_plugins/ cobaltstrike`

```
Volatility 3 Framework 2.0.0
Formatting...0.00		PDB scanning finished                        
  |  PID |        Process | Port | Sleep | Jitter |            Server |   POST_PATH |               x86 Install_Path |                x64 Install_Path |                Pipe | License ID
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | xxxxxxxxxx
* | 4396 | ShellExperienc | 4444 | 10000 |      0 |                   |             | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe | \\.\pipe\msagent_89 | xxxxxxxxxx
* | 4604 |   rundll32.exe |  443 |  5000 |      0 | yellowzinc.corp,/ca | /submit.php | %windir%\syswow64\rundll32.exe | %windir%\sysnative\rundll32.exe |                     | xxxxxxxxxx
```

Or for a given pid

`vol -p ~/github/immersive/volatility_plugins -f Server16-CobaltStrike.raw cobaltstrike --pid 4396`

```
Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
PID	Process	Port	Sleep	Jitter	Server	POST_PATH	x86 Install_Path	x64 Install_Path	Pipe	License ID

4396	ShellExperienc	4444	10000	0			%windir%\syswow64\rundll32.exe	%windir%\sysnative\rundll32.exe	\\.\pipe\msagent_89	1865384295
4396	ShellExperienc	4444	10000	0			%windir%\syswow64\rundll32.exe	%windir%\sysnative\rundll32.exe	\\.\pipe\msagent_89	1865384295

```


### Motivation

Cobalt strike has become increasingly popular with attackers in the last 2 years. A significant number of ransowmare attacks have been observed using Cobalt Strike and the leak of the Conti Ransomware playbook shows how effective this tool is for the attackers. 

There are a number of tools that can process a beacon file and parse the known configuration from a file. These are limited to only being able to parse files / shellcode and can not be used to identify the configuraion of in memory beacons like an SMB pipe deployed in real time. 

A plugin exists for volatility2 but is targetting older versions of Cobalt Strike and is no longer activly maintained. 

This plugin uses yara signatures to identify configuration blocks in any running process so can identify any `migration` or additional beacon confgiurations beyond the initial infection. 


## Rich Headers

This plugin will scan for all runnings proceeses and attempt to recover the rich header. If found the XOR key and the Rich Header Hash will be calculated.

This rich header can be used to identify malware that usess common filenames as the Header Hash will not match, it can also be used to generate an IoC that can be used as part of threat hunting or wider investigations. 

### Source Code

The latest version of the source code can be found at https://github.com/Immersive-Labs-Sec/volatility_plugins/tree/main/richheader

### Usage

`vol -r pretty -f Server16-CobaltStrike.raw -p ./volatility_plugins/ richheader`

```
Volatility 3 Framework 2.0.0
Formatting...0.00               PDB scanning finished                        
  |  PID |        Process |  XOR Key |                 Rich Header Hash
* |  380 |       smss.exe | e8fbb614 | b4da76d938693e03d2d455ef37561772
* |  512 |      csrss.exe | fba319c1 | e4971216867bfffb7beb058dca378a84
* |  592 |      csrss.exe | fba319c1 | e4971216867bfffb7beb058dca378a84
* |  608 |    wininit.exe | 75318913 | f8116f1336d2c70bd16b01ad8be7bb6d
* |  644 |   winlogon.exe | 4bc258ac | c4f0d2eedff3968a8af33cf724e22790
... SNIP ...

* | 1084 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1092 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1148 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1240 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1796 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1836 |    spoolsv.exe | faab1da5 | 5d5d098142e8b226ed97fe3adf7ddf20
* | 1892 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1908 |  LiteAgent.exe | 02f101dd | b9b3e1bdad67eb6429d6456883b69f88
* | 1972 |    svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
* | 1340 |     Sysmon.exe | 8dc13b96 | eacbca12abbaf400b424436a08f1e3e7
* | 2328 |   unsecapp.exe | 39d950c1 | f6bbf14c1865e2d4866e72cdef0ddeef

... SNIP ...

```

or for a given pid

`vol -r pretty -p ~/github/immersive/volatility_plugins -f Server16-CobaltStrike.raw richheader --pid 1892`

```
Volatility 3 Framework 2.0.0
Formatting...0.00		PDB scanning finished                        
  |  PID |     Process |  XOR Key |                 Rich Header Hash
* | 1892 | svchost.exe | fdedd411 | bdf4caf91c4d0776c4021998c204944a
```


### Motivation

Arguably, one of the first tasks when looking at memory forensics is to identify any non legitimate processes running from here you can pivot the investigation. 

The Rich Hash is unique to the Visual Studio compiler environment used to build the binary files. This means it can be used to identify and cluster binary files. 

The primary use case of this extension is to identify malware that is masquerading by name as a legitimate process as the Rich Header Hash will not match. 

A secondary use case is to calculte the Rich Hash and use it as an Indicator of Compromise in a wider investigation or threat hunting scenario. 

This header format is supported by common tools and services like pefile, Yara and Virustotal all of which have support to calcualate and search by a Rich Header Hash or its XOR Key. 


## Password Managers

This one is really eligible on its own but including it in the overall submission. 

This is an update of my existing LastPass plugin taking if from Volatility2 to Volatility3
https://github.com/kevthehermit/volatility_plugins/blob/main/vol3/passwordmanagers/passwordmanagers.py

### Motivation

This one was mostly to become familiar with the new plugin structure as migrating an extension was easier than starting from scratch. This first step allowed me to build the Cobalt Strike plugin. 
