## volatility-docker

### ✨ Project Description

The objective of this project is to create a suite of [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugins for memory forensics of Docker containers. 

To achieve this, we developed improved versions of some of Volatility’s core plugins, intending to make them aware of Linux namespaces. Most of these plugins were never ported from Volatility 2, so they were remade to some extent.

After improving said core plugins, we used the additional namespace-related information they provide and developed the main plugin for this submission - the Docker plugin.

[A full (but readable) explanation of plugin details can be found in the contest submission document](docs/contest_submission.md)



### 🎯 Plugin options
The Docker plugin has a few options:

- **detector** - When choosing this option the plugin will give the investigator a quick indication about the presence of Docker / Docker containers running on the machine.

- **ps** - When choosing this option the plugin will display a table, similar to docker ps command output, that shows the following details about running containers on the machine: container creation time, running command, container-id, is privileged, container process PID.

- **inspect-caps** - When choosing this option a list of running containers will be displayed and the plugin will enumerate the containers’ capabilities.

- **inspect-mounts** - When choosing this option a list of non-default mounts will be displayed with information about the associated container, mount paths, and mount options.

- **inspect-networks** - When choosing this option a list of Docker networks will be displayed by their IP segments and the containers that are related to them.


### ⚙ Installation

All plugins are located in the `plugins` folder. Copy them to your Volatility 3 directory under `volatility3/volatility3/framework/plugins/linux`.

Some other framework extensions are required. They are located under `volatility3 changes`, and are organized in the same directory structure as their location within Volatility 3. Simply copy them to the same location (overwrite existing files if needed).

### ✍️ Contributors

- [**Ofek Shaked**](https://github.com/oshaked1)
- [**Amir Sheffer**](https://github.com/amir9339)
