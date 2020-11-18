# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Tuple, List, Iterable, Union

from volatility.framework import renderers, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.plugins.linux import pslist

vollog = logging.getLogger(__name__)

DEFAULT_PIDS_VALUE = [1]


class MountInfo(plugins.PluginInterface):
    """Lists mount points in processes mount namespaces"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description="Memory layer for the kernel",
                                                     architectures=['Intel32', 'Intel64']),
            requirements.SymbolTableRequirement(name='vmlinux',
                                                description="Linux kernel symbols"),
            requirements.PluginRequirement(name='pslist',
                                           plugin=pslist.PsList, version=(1, 0, 0)),
            requirements.ListRequirement(name='pids',
                                         description="Filter on specific process IDs. Default is pid 1",
                                         element_type=int,
                                         default=DEFAULT_PIDS_VALUE,
                                         optional=True),
            requirements.BooleanRequirement(name='all',
                                            description="Shows information about mount points for each process mount "
                                            "namespace. It could take a while depending on the number of processes "
                                            "running. Note that if this argument is not specified it uses the root "
                                            "mount namespace based on pid 1.",
                                            optional=True,
                                            default=False),
            requirements.BooleanRequirement(name='mount-format',
                                            description="Shows a brief summary of a process mount points information "
                                            "with similar output format to the older /proc/[pid]/mounts or the "
                                            "user-land command 'mount -l'.",
                                            optional=True,
                                            default=False),
        ]

    def _get_symbol_fullname(self, symbol_basename: str) -> str:
        """Given a short symbol or type name, it returns its full name"""
        return self.config['vmlinux'] + constants.BANG + symbol_basename

    @classmethod
    def _do_get_path(cls, mnt, fs_root) -> Union[None, str]:
        """It mimics the Linux kernel prepend_path function."""
        vfsmnt = mnt.mnt
        dentry = vfsmnt.get_mnt_root()

        path_reversed = []
        while dentry != fs_root.dentry or vfsmnt.vol.offset != fs_root.mnt:
            if dentry == vfsmnt.get_mnt_root() or dentry.is_root():
                parent = mnt.get_mnt_parent().dereference()
                # Escaped?
                if dentry != vfsmnt.get_mnt_root():
                    return None

                # Global root?
                if mnt.vol.offset != parent.vol.offset:
                    dentry = mnt.get_mnt_mountpoint()
                    mnt = parent
                    vfsmnt = mnt.mnt
                    continue

                return None

            parent = dentry.d_parent
            dname = dentry.d_name.name_as_str()
            path_reversed.append(dname.strip('/'))
            dentry = parent

        path = '/' + '/'.join(reversed(path_reversed))
        return path

    @classmethod
    def get_mountinfo(cls, mnt, task) -> Union[None, Tuple[int, int, str, str, str, List[str], List[str], str, str,
                                                           List[str]]]:
        """Extract various information about a mount point.
        It mimics the Linux kernel show_mountinfo function.
        """
        mnt_root = mnt.get_mnt_root()
        if not mnt_root:
            return None

        mnt_root_path = mnt_root.path()
        superblock = mnt.get_mnt_sb()

        mnt_id = mnt.mnt_id  # type: int
        parent_id = mnt.mnt_parent.mnt_id  # type: int

        st_dev = "{0}:{1}".format(superblock.major, superblock.minor)

        path_root = cls._do_get_path(mnt, task.fs.root)
        if path_root is None:
            return None

        mnt_opts = []  # type: List[str]
        mnt_opts.append(mnt.get_flags_access())
        mnt_opts.extend(mnt.get_flags_opts())

        # Tagged fields
        fields = []  # type: List[str]
        if mnt.is_shared():
            fields.append("shared:{}".format(mnt.mnt_group_id))

        if mnt.is_slave():
            master = mnt.mnt_master.mnt_group_id
            fields.append("master:{}".format(master))
            dominating_id = mnt.get_dominating_id(task.fs.root)
            if dominating_id and dominating_id != master:
                fields.append("propagate_from:{}".format(dominating_id))

        if mnt.is_unbindable():
            fields.append("unbindable")

        mnt_type = superblock.get_type()

        devname = mnt.get_devname()
        if not devname:
            devname = "none"

        sb_opts = []  # type: List[str]
        sb_opts.append(superblock.get_flags_access())
        sb_opts.extend(superblock.get_flags_opts())

        return mnt_id, parent_id, st_dev, mnt_root_path, path_root, mnt_opts, fields, mnt_type, devname, sb_opts

    def _get_mnt_namespace_mountpoints(self, mnt_namespace):
        mnt_type = self._get_symbol_fullname('mount')
        if not self.context.symbol_space.has_type(mnt_type):
            mnt_type = self._get_symbol_fullname('vfsmount')

        for mount in mnt_namespace.list.to_list(mnt_type, 'mnt_list'):
            yield mount

    def _get_tasks_mountpoints(self, pids: Iterable[int]):
        context = self.context
        layer_name = self.config['primary']
        symbol_table = self.config['vmlinux']

        pid_filter = pslist.PsList.create_pid_filter(pids)
        tasks = pslist.PsList.list_tasks(context, layer_name, symbol_table, filter_func=pid_filter)
        for task in tasks:
            if not (task.fs and task.fs.root and task.nsproxy and task.nsproxy.mnt_ns):
                vollog.log(constants.LOGLEVEL_VVVV, "PID %d doesn't have all the information required", task.pid)
                continue

            mnt_namespace = task.nsproxy.mnt_ns
            mount_ns_id = mnt_namespace.get_inode()

            for mount in self._get_mnt_namespace_mountpoints(mnt_namespace):
                yield task, mount, mount_ns_id

    def _generator(self):
        pids = self.config.get('pids', None)
        if self.config.get('all', False):
            pids = None

        for task, mnt, mnt_ns_id in self._get_tasks_mountpoints(pids=pids):
            pid = task.pid

            mnt_info = self.get_mountinfo(mnt, task)
            if mnt_info is None:
                continue

            mnt_id, parent_id, st_dev, mnt_root, path_root, mnt_opts, fields, mnt_type, devname, sb_opts = mnt_info

            if self.config.get('mount-format', False):
                all_opts = set()
                all_opts.update(mnt_opts)
                all_opts.update(sb_opts)
                all_opts_str = "{0}".format(",".join(all_opts))

                fields_values = devname, path_root, mnt_type, all_opts_str
            else:
                mnt_opts_str = ",".join(mnt_opts)
                fields_str = " ".join(fields)
                sb_opts_str = ",".join(sb_opts)

                fields_values = (mnt_id, parent_id, st_dev, mnt_root, path_root, mnt_opts_str, fields_str, mnt_type,
                                 devname, sb_opts_str)  # type: ignore

            fields_values += (mnt_ns_id, pid)  # type: ignore

            yield (0, fields_values)

    def run(self):
        pids = self.config.get('pids', None)
        if self.config.get('all', False) and pids != DEFAULT_PIDS_VALUE:
            raise ValueError("Unable to use --all and specified a pid")

        if self.config.get('mount-format', False):
            columns = [("devname", str), ("path", str), ("fstype", str), ("mnt_opts", str)]
        else:
            # /proc/[pid]/mountinfo output format
            columns = [("mount id", int), ("parent_id", int), ("major:minor", str), ("root", str),
                       ("mount_point", str), ("mount_options", str), ("fields", str), ("fstype", str),
                       ("mount_src", str), ("sb_options", str)]  # type: ignore

        columns.extend([("mnt_ns_id", int), ("PID", int)])  # type: ignore

        return renderers.TreeGrid(columns, self._generator())  # type: ignore
