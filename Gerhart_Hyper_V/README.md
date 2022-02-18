# Note about DLL and SYS 

Please contact https://github.com/gerhart01 for the most recent DLL and SYS files.

# Instructions

2 files modified:

"volatility3\framework\layers\hyperv.py"
"volatility3\framework\automagic\stacker.py"

1. install modules (yara-python, pefile, pycpryptodome)

	pip install yara-python according https://github.com/VirusTotal/yara-python
	pip install pefile
	pip install pycryptodome

   install VS redist for libyara (if you see error messages with libyara module)

	Microsoft Visual C++ 2010 Redistributable Package
	https://www.microsoft.com/en-US/download/details.aspx?id=26999
	add C:\Python39x64\Lib\site-packages\python39x64\DLLs to path or copy libyara.dll to C:\Python39x64\DLLs

2. copy hyperv.py to volatility3\framework\layers
3. modify stacker.py (physical_layer)

 #
 # hvlib integration
 #

 from volatility3.framework.layers import hyperv
 import os

 #
 # hvlib integration
 #

 dir_win = os.getenv('WINDIR')
 dir_win = dir_win.replace('\\','/').lower()

 hvlib_fn = "file:///"+dir_win+"/hvmm.dmp"
 if location.lower() == hvlib_fn:
    print("Hyper-V layer is active")
    physical_layer = hyperv.FileLayer(new_context, current_config_path, current_layer_name)
 else:
    physical_layer = physical.FileLayer(new_context, current_config_path, current_layer_name)

4. copy hvlib.py, hvlib.dll and hvmm.sys to <python_dir>\Lib\site-packages (f.e. C:\Python39x64\Lib\site-packages).
	If you use some python virtual environment plugins, you need copy files inside it:
	for example to venv\Lib\site-packages for virtualenv.
5. Copy file hvmm.dmp to C:\Windows\hvmm.dmp (it needed, because volatility needs read real file)

python.exe vol.py -vv -f "C:\windows\hvmm.dmp" windows.pslist

if you often see messages: "KDBG block is not found. Probably, some of ntoskrnl sections was moved in pagefile", disable pagefile in guest OS (Control Panel - System-Advanced System Settings-Performance-Advanced-Change-No paging file)