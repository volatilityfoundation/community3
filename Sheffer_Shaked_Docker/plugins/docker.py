from typing import List
import logging
from datetime import datetime

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.objects import utility

from volatility3.plugins.linux import pslist, mount, ifconfig

vollog = logging.getLogger(__name__)

DOCKER_MAC_VENDOR_STARTER       = "02:42"
DOCKER_INTERFACE_STARTER        = "docker"
VETH_NAME_STARTER               = "eth"
DOCKER_MOUNT_PATH               = "/var/lib/docker/"
CONTAINERD_SHIM_PROC_STARTER    = "containerd-shim"
OVERLAY                         = "overlay"
CONTAINERD_PROCESS_COMMAND      = "containerd-shim"
DOCKER_CGROUPS_PATH             = "/sys/fs/cgroup/memory/docker"
DOCKER_CGROUPS_PATH_LEN         = 5

MOUNTS_ABS_STARTING_PATH_WHITELIST = (
    "/sys/fs/cgroup", # Default mount
)

MOUNTS_ABS_ENDING_PATH_WHITELIST = (
    "/merged", # Merged dir mount only, not sus
    "/merged/dev", # Default mount
    "/resolv.conf", # Default mount
    "/hostname", # Default mount
    "/hosts", # Default mount
    "/merged/run/systemd/resolve/stub-resolv.conf" # Default mount,

)

MOUNTS_PATH_WHITELIST = (
    "/proc", # Default mounts
    "/sys", # Default mount
    "/dev"  # Default mount
)

CAPABILITIES = [
    # Defined at: https://elixir.bootlin.com/linux/v5.15-rc6/source/include/uapi/linux/capability.h
    "CAP_CHOWN", 
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP__SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE"
]


class Detector():
    """ This class has set of functions for docker detection on system """

    def __init__(self, context, vmlinux, tasks_list) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list # Tasks objects list
        self.mounts = mount.Mount.get_all_mounts(self.context, self.vmlinux.name) # Get mounts from plugin
        self.net_devices = ifconfig.Ifconfig.get_net_devs(self.context, self.vmlinux.name)

    @staticmethod
    def _detect_docker_network_interface(name, mac_addr) -> bool:
        """ 
        This function search for an docker standard interface. 
        Looking for an interface whose name starts with 'docker' and its MAC vendor starts with '02:42' (the last 4 bytes are calculated on the fly)
        """

        return name.startswith(DOCKER_INTERFACE_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    @staticmethod
    def _detect_docker_veths(name, mac_addr) -> bool:
        """ 
        This function is looking for virtual interface that are used inside containers.
        Almost the same way as in _detect_docker_network_interface function.
        It looking for interfaces starting with the name 'eth' and the MAC address '02:42'
        """

        return name.startswith(VETH_NAME_STARTER) and mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER)

    @staticmethod
    def _detect_overlay_fs(fstype, path) -> bool:
        """
        This function is looking for 'overlay' FS mounted inside docker standard path:
            /var/lib/docker/
        These FS are used as container's FS
        """

        return OVERLAY in fstype and path.startswith(DOCKER_MOUNT_PATH)
    
    @staticmethod
    def _detect_containerd_shim(proc_name) -> bool:
        """
        Containerd-shim is the parent process of all docker containers. Example can be seen in this output of `ps auxf` command:
            root        6398 713104  3120 16:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id
            root        6417   2508    68 16:00  \_ sleep 3000
        This function is looking for a process of containerd-shim in processes list
        """

        return CONTAINERD_SHIM_PROC_STARTER in proc_name

    def generate_detection_list(self):
        """ 
        This function generates a list of values that indicates a presence of containers / docker daemon on machine 
        """

        # Set default values
        docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running = False, False, False, False

        # Get processes list from memory using pslist plugin
        for task in self.tasks_list:
            proc_name = utility.array_to_string(task.comm)
            
            if self._detect_containerd_shim(proc_name):
                container_shim_running = True
                break
        
        # Get mounts list from mem using mount plugin and look for overlay FS mounts inside docker's dir
        for task, mnt in self.mounts:

            _id, _pid, _devname, path, _abs_type, fstype, _access, _flags = mount.Mount.get_mount_info(self.context, self.vmlinux.name, mnt, task=task)

            if self._detect_overlay_fs(fstype, path):
                overlay_fs_exists = True
                break
    
        # Look for docker related interfaces
        for _net_ns, net_dev in self.net_devices:
            name, mac_addr, _ipv4_addr, ipv4_prefixlen, ipv6_addr, ipv6_prefixlen, promisc \
                = ifconfig.Ifconfig.get_net_dev_info(self.context, self.vmlinux.name, net_dev)

            if self._detect_docker_network_interface(name, mac_addr):
                docker_eth_exists = True
            
            if self._detect_docker_veths(name, mac_addr):
                docker_veth_exists = True

        yield docker_eth_exists, docker_veth_exists, overlay_fs_exists, container_shim_running


class Ps():
    def __init__(self, context, vmlinux, tasks_list) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list # Tasks objects list

    def get_containers_pids(self):
        """ 
        This function iterates each task in tasks list 
            and search for containerd-shim process. 
        After it found those processes it searches for
            processes that are bound to those shim processes 
            and returns their PIDs
        """

        containerd_shim_processes_pids = []
        containers_pids = []
        
        # Iterate processes list and search for "containerd-shim" processes which are bound to containers
        for task in self.tasks_list:
            comm = utility.array_to_string(task.comm)

            # If the process is an instance of containerd-shim, append it's process id to list
            if comm == CONTAINERD_PROCESS_COMMAND:
                containerd_shim_processes_pids.append(task.pid)

        # Search for containers that are bound to shim list
        for task in self.tasks_list:
            if task.parent.pid in containerd_shim_processes_pids:
                containers_pids.append(task.pid)
        return containers_pids
    
    def get_container_id(self, container_pid):
        """ 
        This function gets a PID of a container
        It enumerates process's mount points using linux.mount
        Then, it iterates container's process mounts and search for 
            container_id which is the name of container's dir under cgroups dir
            https://docs.docker.com/config/containers/runmetrics/
        """

        pid_filter = pslist.PsList.create_pid_filter([container_pid]) 
        process_mounts = mount.Mount.get_mounts(self.context, self.vmlinux.name, pid_filter) # Extract mounts for this process
        process_mounts = [mount.Mount.get_mount_info(self.context, self.vmlinux.name, mnt, task=task) for task, mnt in process_mounts] # Extract mount info for each mount point

        # Iterate each mount in mounts list
        for _mnt_id, _parent_id, _devname, _path, absolute_path, _fs_type, _access, _flags in process_mounts:
            
            splitted_path = absolute_path.split("/")

            # Search for container's merged dir (container's FS) under overlay or overlay2 dir
            if absolute_path.startswith(DOCKER_CGROUPS_PATH):
                container_id = splitted_path[-1] # Extract container_id from path
                return container_id
        return None
    
    def get_init_task_cap(self):
        """ 
        These function returns init's task effective capabilities.
        This value helps detect containers running with --privileged flag because they get all capabilities, and are equal to init task.

        return init_task_cap (int) if succeed, None if failed
        """

        init_task = self.tasks_list[0]

        # Double check if init task is found
        if init_task.pid == 1:
            init_task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, init_task, credinfo=True)
            init_task_cap = init_task_info.cap_eff
            return init_task_cap
        else:
            return None

    def generate_list(self, extended=True):
        """ 
        This function generates a list of running containers in this format:
        creation_time, command, container_id, is_priv, pid
        """

        containers_pids = self.get_containers_pids()

        priv_container_eff_caps = self.get_init_task_cap()
        
        # Search for container's tasks
        for task in self.tasks_list:
            for pid in containers_pids:
                if task.pid == pid:
                    command = utility.array_to_string(task.comm)
                    container_id = self.get_container_id(task.pid)

                    # Extract creds from task and check if container runs as priv. Note that there is a class that checks the exact container's creds
                    task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, task, credinfo=True)
                    creation_time = task_info.start_time
                    creation_time = datetime.utcfromtimestamp(creation_time).isoformat(sep=' ', timespec='milliseconds')
                    effective_uid = task_info.eff_uid
                    is_priv = task_info.cap_eff == priv_container_eff_caps

                    if extended:
                        yield creation_time, command, container_id, is_priv, pid, effective_uid
                    else:
                        yield container_id[:11], command, creation_time, pid


class InspectCaps():
    """ This class has methods for capabilites extraction and convertion """

    def __init__(self, context, vmlinux, tasks_list, containers_pids) -> None:
        """
        tasks_list - A list of tasks, extracted from memory using Pslist plugin
        containers_pids - A list of containers pids to inspect 
        """

        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids

    @staticmethod
    def _caps_hex_to_string(caps) -> list:
        """ 
        Linux active capabilities are saved as a bits sequense where each bit is a flag for each capability.
        This function iterate each flag in seq and if it's active it adds the specific capability to the list as a string represents it's name.
        """
        
        active_caps = []
        caps = abs(caps) # The method below doesn't work for negative numbers
        
        bits_seq = bin(caps)[2:]
        bits_seq = bits_seq[::-1] # Reverse flags seq

        # For each flag in caps sequense, if cap is active, append to list
        for i, digit in enumerate(bits_seq):
            
            # If flag is active, append the right cap to the list
            if digit == "1":
                active_caps.append(CAPABILITIES[i])
        return active_caps
    
    def generate_containers_caps_list(self):
        """ This function iterate each container pid and convert its effective capabilities to list of caps """

        # Iterate each pid in containers list and search for it's task
        for pid in self.containers_pids:
            for task in self.tasks_list:
                if task.pid == pid:

                    # Get container-id from Ps class
                    container_id = Ps(self.context, self.vmlinux, self.tasks_list).get_container_id(pid)
                    
                    # Get task's creds
                    task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, task, credinfo=True)
                    effective_caps = task_info.cap_eff
                    effective_caps_list = self._caps_hex_to_string(effective_caps)
                    yield pid, container_id, hex(effective_caps), ','.join(effective_caps_list)


class InspectMounts():
    """ This class has methods for interesting mounts extraction """

    def __init__(self, context, vmlinux, tasks_list, containers_pids) -> None:
        """
        tasks_list - A list of tasks, extracted from memory using Pslist plugin
        containers_pids - A list of containers pids to inspect 
        """

        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids

    def generate_mounts_list(self, extended=True):
        """
        This function generates a list of containers unusual mount points.
        For each container that Ps class found it checks for mounts in it mount namespace 
            and compare it with it a whitelist that contains normal mounts paths.
        It returns: container pid, container_id and details about the mount taken from linux.mount.
        """

        # For each container, check for unusual mounts        
        for pid in self.containers_pids:
            pid_filter = pslist.PsList.create_pid_filter([pid])
            process_mounts = mount.Mount.get_mounts(self.context, self.vmlinux.name, pid_filter) # Extract mounts for this process
            process_mounts = [mount.Mount.get_mount_info(self.context, self.vmlinux.name, mnt, task=task) for task, mnt in process_mounts] # Extract mount info for each mount point

            # Iterate each mount in mounts list
            for mnt_id, parent_id, devname, path, absolute_path, fs_type, access, flags in process_mounts:
                if (not absolute_path.startswith(MOUNTS_ABS_STARTING_PATH_WHITELIST)
                    and not absolute_path.endswith(MOUNTS_ABS_ENDING_PATH_WHITELIST)
                    and not path.startswith(MOUNTS_PATH_WHITELIST)
                    and path):
                    
                    # Get container-id from Ps class
                    container_id = Ps(self.context, self.vmlinux, self.tasks_list).get_container_id(pid)

                    if extended:
                        yield pid, container_id, mnt_id, parent_id, devname, path, absolute_path, fs_type, access, flags
                    else:
                        yield pid, container_id[:11], path, absolute_path, fs_type


class InspectNetworks():
    def __init__(self, context, vmlinux, tasks_list, containers_pids) -> None:
        self.context = context # Volatility req
        self.vmlinux = vmlinux # Volatility req
        self.tasks_list = tasks_list
        self.containers_pids = containers_pids
        self.net_devices = ifconfig.Ifconfig.get_net_devs(self.context, self.vmlinux.name)
    
    def list_docker_networks(self) -> dict:
        """
        This function will list docker networks by walking on interfaces list,
            extract interfaces that their MAC adress starts with Docker vendor ID,
            match between containers net ns id and intreface's related net ns and then return a dict
            of networks (represented by network segment) and the containers connected to it.
        Note that this function does not support ipv6 - only docker containers
        """

        containers_net_ns_dict = {
            # net_ns: (container_id, pid)
        }

        # Return dict
        networks_dict = {
            # network_segment: [(container_id, pid)]
        }

        # Get all containers tasks
        for task in self.tasks_list:
            if task.pid in self.containers_pids:
                # Extract ns info from task to get network ns
                task_info = pslist.PsList.get_task_info(self.context, self.vmlinux.name, task, nsinfo=True)
                net_ns_id = task_info.net_ns

                # Get container-id from Ps class
                container_id = Ps(self.context, self.vmlinux, self.tasks_list).get_container_id(task.pid)
                containers_net_ns_dict[net_ns_id] = (container_id, task.pid)

        # Iterate devices list and get Docker devices
        for net_ns, net_dev in self.net_devices:
            _name, mac_addr, ipv4_addr, _ipv4_prefixlen, _ipv6_addr, _ipv6_prefixlen, _promisc \
                = ifconfig.Ifconfig.get_net_dev_info(self.context, self.vmlinux.name, net_dev)

            # If interface recognized as a docker related interface
            if mac_addr.startswith(DOCKER_MAC_VENDOR_STARTER):
                segment = ipv4_addr.split(".")
                segment = f"{segment[0]}.{segment[1]}" # Get only first two octats of ip addr

                containers_net_ns_list = containers_net_ns_dict.keys() # Get all containers net ns ids
                
                # If network ns is in containers list
                # This if statement excludes docker0 interface that lives inside the native net ns 
                #   and it's not related to a specific container
                if net_ns in containers_net_ns_list:
                    ns_related_container = containers_net_ns_dict[net_ns]
                else:
                    continue

                # If network segment is already a key in the dict, append container to its list
                if segment in networks_dict:
                    networks_dict[segment].append(ns_related_container)
                else:
                    networks_dict[segment] = [ns_related_container]
        return networks_dict

    def generate_networks_list(self, extended=True):
        """ This function is used to generate networks table and it called by main run function """

        networks_dict = self.list_docker_networks()

        # Yield each network as a table row
        for network in networks_dict:
            containers = networks_dict[network]

            # If extended return full container_id else, return short id
            if extended:
                containers_ids = [container[0] for container in containers] 
            else:
                containers_ids = [container[0][:11] for container in containers]
            containers_ids = ','.join(containers_ids)
            pids = [str(container[1]) for container in containers]
            pids = ','.join(pids)

            # If extended yield also pids
            if extended:
                yield network, containers_ids, pids
            else:
                yield network, containers_ids


class Docker(interfaces.plugins.PluginInterface):
    """ Main class for docker plugin """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name='kernel',
                                            description='Linux kernel',
                                            architectures=['Intel32', 'Intel64']),
                requirements.PluginRequirement(name = 'pslist',
                                                plugin = pslist.PsList,
                                                version = (2, 0, 0)),
                requirements.PluginRequirement(name = 'mount',
                                                plugin = mount.Mount,
                                                version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'ifconfig',
                                                plugin = ifconfig.Ifconfig,
                                                version = (1, 0, 0)),
                
                # Plugin options
                requirements.BooleanRequirement(name='detector',
                                            description='Detect Docker daemon / containers in memory',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='ps',
                                            description='List of running containers',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='ps-extended',
                                            description='Extended list of running containers',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-caps',
                                            description='Inspect containers capabilities',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-mounts',
                                            description='Show a list of containers mounts',
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-mounts-extended',
                                            description="Show detailed list of containers mounts",
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-networks',
                                            description="Show detailed list of containers networks",
                                            optional=True,
                                            default=False),
                requirements.BooleanRequirement(name='inspect-networks-extended',
                                            description="Show detailed list of containers networks",
                                            optional=True,
                                            default=False),
                ]

    def _generator(self):

        vmlinux = self.context.modules[self.config['kernel']]

        tasks_list = list(pslist.PsList.list_tasks(self.context, vmlinux.name)) # Generate tasks list from memory using linux.pslist

        # If user chose detector, generate detection table
        if self.config.get("detector"):
            detection_values = Detector(self.context, vmlinux, tasks_list).generate_detection_list()
            
            # Actually there is only one row...
            for row in detection_values:
                yield (0, row)

        # If user chose ps, generate containers list
        if self.config.get("ps"):
            for container_row in Ps(self.context, vmlinux, tasks_list).generate_list(extended=False):
                yield (0, container_row)

        # If user chose ps, generate containers list
        if self.config.get("ps-extended"):
            for container_row in Ps(self.context, vmlinux ,tasks_list).generate_list(extended=True):
                yield (0, container_row)

        # If user chose inspect-caps, generate containers list and check their capabilities
        if self.config.get("inspect-caps"):
            containers_pids = Ps(self.context, vmlinux, tasks_list).get_containers_pids()
            for container_row in InspectCaps(self.context, vmlinux, tasks_list, containers_pids).generate_containers_caps_list():
                yield (0, container_row)

        # If user chose inspect-mounts, generate containers list and check their mounts
        if self.config.get("inspect-mounts"):
            containers_pids = Ps(self.context, vmlinux, tasks_list).get_containers_pids()
            for container_row in InspectMounts(self.context, vmlinux, tasks_list, containers_pids).generate_mounts_list(extended=False):
                yield (0, container_row)

        # If user chose inspect-mounts, generate containers list and check their mounts
        if self.config.get("inspect-mounts-extended"):
            containers_pids = Ps(self.context, vmlinux, tasks_list).get_containers_pids()
            for container_row in InspectMounts(self.context, vmlinux, tasks_list, containers_pids).generate_mounts_list(extended=True):
                yield (0, container_row)

        # If user chose inspect-networks
        if self.config.get("inspect-networks"):
            containers_pids = Ps(self.context, vmlinux, tasks_list).get_containers_pids()
            for container_row in InspectNetworks(self.context, vmlinux, tasks_list, containers_pids).generate_networks_list(extended=False):
                yield (0, container_row)
        
        # If user chose inspect-networks
        if self.config.get("inspect-networks-extended"):
            containers_pids = Ps(self.context, vmlinux, tasks_list).get_containers_pids()
            for container_row in InspectNetworks(self.context, vmlinux, tasks_list, containers_pids).generate_networks_list(extended=True):
                yield (0, container_row)

    def run(self):

        columns = []

        if not self.config.get("detector") and not self.config.get("inspect-caps") \
            and not self.config.get("ps") and not self.config.get("ps-extended") \
            and not self.config.get("inspect-mounts") and not self.config.get("inspect-mounts-extended") \
            and not self.config.get("inspect-networks") and not self.config.get("inspect-networks-extended"):
            
            vollog.error('No option selected')
            raise exceptions.PluginRequirementException('No option selected')

        if self.config.get("detector"):
            columns.extend([('Docker inetrface', bool), ('Docker veth', bool), 
                            ('Mounted Overlay FS', bool), ('Containerd-shim is running', bool)])

        if self.config.get("ps"):
            columns.extend([('Container ID', str), ('Command', str), ('Creation Time (UTC)', str),
                            ('PID', int)])

        if self.config.get("ps-extended"):
            columns.extend([('Creation time (UTC)', str), ('Command', str), ('Container ID', str),
                            ('Is privileged', bool), ('PID', int), ('Effective UID', int)])
        
        if self.config.get("inspect-caps"):
            columns.extend([('PID', int), ('Container ID', str), ('Effective Capabilities Mask', str), ('Effective Capabilities Mames', str)])
        
        if self.config.get("inspect-mounts"):
            columns.extend([('PID', int), ('Container ID', str), ('Container Path', str), 
                            ('Host Path', str), ('FS type', str)])
        
        if self.config.get("inspect-mounts-extended"):
            columns.extend([('PID', int), ('Container ID', str), ('Mount ID', int), 
                            ('Parent ID', int), ('Device name', str), ('Path', str), 
                            ('Absolute Path', str), ('FS Type', str), ('Access', str),
                            ('Flags', str)])

        if self.config.get("inspect-networks"):
            columns.extend([('Network /16 Segment', str), ('Containers IDs', str)])

        if self.config.get("inspect-networks-extended"):
            columns.extend([('Network /16 Segment', str), ('Containers IDs', str), ('Containers PIDs', str)])

        return renderers.TreeGrid(columns, self._generator())