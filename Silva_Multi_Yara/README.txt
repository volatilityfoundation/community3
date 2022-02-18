Requirements:
Python3 needs to be installed
pygit2 needs to be installed - https://www.pygit2.org/install.html#quick-install

To run on windows
Go to the volatility3 folder on windows and run the following command:
python.exe vol.py -p="{location of the plugin file}" -f {memory image to be used} basicplugin --rules|category="{Yara-rules|reversinglabs-yara-rules|malware-ioc|signature-base|Yara-Rules}"

To run on linux
vol.py -p="{location of the plugin file}" -f {memory image to be used} basicplugin --rules|category="{Yara-rules|reversinglabs-yara-rules|malware-ioc|signature-base|Yara-Rules}"|clone|pull

Options:
--category : runs rules from those git mentioned in the command, the clone command needs to be run before this is used
--clone : clones all the git repositories to their respective folders
--pull : updates all the git repositories

Windows: python3.9.exe vol.py -p="plugins\" -f victim.raw multiyara.MultiYara
Linux: python3.9.exe vol.py -p="/home/user/volatility3/plugins/" -f victim.raw multiyara.MultiYara
