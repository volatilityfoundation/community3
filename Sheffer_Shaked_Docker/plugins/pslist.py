# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Callable, Iterable, List, Any
from dataclasses import dataclass
import logging
from datetime import datetime

from volatility3.framework import renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework import exceptions


vollog = logging.getLogger(__name__)


@dataclass
class TaskInfo:
    """Class that holds high level information about a task."""
    # generic info
    pid: int = -1
    ppid: int = -1
    name: str = ''
    start_time: float = 0

    # namespace info
    pid_in_ns: int = -1
    uts_ns: int = -1
    ipc_ns: int = -1
    mnt_ns: int = -1
    net_ns: int = -1
    pid_ns: int = -1
    user_ns: int = -1

    # credinfo
    real_uid: int = -1
    real_gid: int = -1
    eff_uid: int = -1
    eff_gid: int = -1
    cap_inh: int = -1
    cap_prm: int = -1
    cap_eff: int = -1
    cap_bnd: int = -1

    def tuple(self, nsinfo: bool = False, credinfo: bool = False):
        time_str = datetime.utcfromtimestamp(self.start_time).isoformat(sep=' ', timespec='milliseconds')
        lst = [self.pid, self.ppid, self.name, time_str]
        if nsinfo:
            lst.extend([self.pid_in_ns, self.uts_ns, self.ipc_ns, self.mnt_ns, self.net_ns, self.pid_ns, self.user_ns])
        if credinfo:
            lst.extend([self.real_uid, self.real_gid, self.eff_uid, self.eff_gid, format_hints.Hex(self.cap_inh),
                        format_hints.Hex(self.cap_prm), format_hints.Hex(self.cap_eff), format_hints.Hex(self.cap_bnd)])
        
        return tuple(lst)


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.ListRequirement(name='pid',
                                         description='Filter on specific process IDs',
                                         element_type=int,
                                         optional = True),
            requirements.BooleanRequirement(name='nsinfo',
                                            description='Display namespace information',
                                            optional=True,
                                            default=False),
            requirements.BooleanRequirement(name='credinfo',
                                            description='Display credentials and capability information',
                                            optional=True,
                                            default=False)
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def filter_func(x):
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    @classmethod
    def get_task_info(cls,
                      context: interfaces.context.ContextInterface,
                      vmlinux_module_name: str,
                      task: symbols.linux.extensions.task_struct,
                      boot_time: int = None,
                      nsinfo: bool = False,
                      credinfo: bool = False) -> TaskInfo:
        """Extract information about a task."""
        vmlinux = context.modules[vmlinux_module_name]

        info = TaskInfo()

        # extract general info
        info.pid = task.pid
        info.ppid = 0
        if task.parent:
            info.ppid = task.parent.pid
        info.name = utility.array_to_string(task.comm)
        if boot_time is None:
            boot_time = symbols.linux.LinuxUtilities.get_boot_time(vmlinux)
        info.start_time = task.get_start_time(boot_time)
        
        # extract namespace information
        if nsinfo:
            # Get namespace IDs.
            # This is full of try and excepts because different kernel versions
            # have different available namespace types.
            # If a certain namespace type does not exist, -1 is returned for its value.
            if task.has_member('nsproxy'):
                nsproxy = task.nsproxy.dereference()

                # get uts namespace
                try:
                    info.uts_ns = nsproxy.get_uts_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.uts_ns = -1
                
                # get ipc namespace
                try:
                    info.ipc_ns = nsproxy.get_ipc_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.ipc_ns = -1

                # get mount namespace
                try:
                    info.mnt_ns = nsproxy.get_mnt_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.mnt_ns = -1
                
                # get net namespace
                try:
                    info.net_ns = nsproxy.get_net_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.net_ns = -1
                
                # get pid namespace
                try:
                    info.pid_ns = task.get_pid_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.pid_ns = -1
                
                # get user namespace
                try:
                    info.user_ns = nsproxy.get_user_ns().get_inum()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.user_ns = -1
                
                # get pid from within the namespace
                try:
                    info.pid_in_ns = task.get_namespace_pid()
                except (AttributeError, exceptions.PagedInvalidAddressException):
                    info.pid_in_ns = -1
            
            # no task -> nsproxy
            else:
                vollog.error('Unable to extract namespace information (no task -> nsproxy member)')
        
        # extract credentials and capability information
        if credinfo:
            cred = task.cred.dereference()
            try:
                if cred.uid.has_member('val'):
                    info.real_uid = cred.uid.val
                else:
                    info.real_uid = cred.uid
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                if cred.gid.has_member('val'):
                    info.real_gid = cred.gid.val
                else:
                    info.real_gid = cred.gid
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                if cred.euid.has_member('val'):
                    info.eff_uid = cred.euid.val
                else:
                    info.eff_uid = cred.euid
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                if cred.egid.has_member('val'):
                    info.eff_gid = cred.egid.val
                else:
                    info.eff_gid = cred.egid
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                info.cap_inh = cred.cap_inheritable.to_int()
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                info.cap_prm = cred.cap_permitted.to_int()
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                info.cap_eff = cred.cap_effective.to_int()
            except exceptions.PagedInvalidAddressException:
                pass
            try:
                info.cap_bnd = cred.cap_bset.to_int()
            except exceptions.PagedInvalidAddressException:
                pass

        return info

    def _generator(self):
        vmlinux = self.context.modules[self.config['kernel']]
        nsinfo = self.config.get('nsinfo', False)
        credinfo = self.config.get('credinfo', False)

        boot_time = symbols.linux.LinuxUtilities.get_boot_time(vmlinux)

        for task in self.list_tasks(self.context,
                                    self.config['kernel'],
                                    filter_func = self.create_pid_filter(self.config.get('pid', None))):
            taskinfo = self.get_task_info(self.context, self.config['kernel'], task, boot_time=boot_time, nsinfo=nsinfo, credinfo=credinfo)
            yield (0, taskinfo.tuple(nsinfo=nsinfo, credinfo=credinfo))

    @classmethod
    def list_tasks(
            cls,
            context: interfaces.context.ContextInterface,
            vmlinux_module_name: str,
            filter_func: Callable[[int], bool] = lambda _: False) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            Process objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        init_task = vmlinux.object_from_symbol(symbol_name = "init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            if not filter_func(task):
                yield task

    def run(self):
        columns = [('PID', int), ('PPID', int), ('COMM', str), ('Start Time (UTC)', str)]

        if self.config.get('nsinfo', False):
            columns.extend([('PID in NS', int), ('UTS NS', int), ('IPC NS', int),
                            ('MNT NS', int), ('NET NS', int), ('PID NS', int), ('USER NS', int)])

        if self.config.get('credinfo', False):
            columns.extend([('Real UID', int), ('Real GID', int), ('Eff UID', int),
                            ('Eff GID', int), ('CapInh', format_hints.Hex),
                            ('CapPrm', format_hints.Hex), ('CapEff', format_hints.Hex), ('CapBnd', format_hints.Hex)])

        return renderers.TreeGrid(columns, self._generator())
