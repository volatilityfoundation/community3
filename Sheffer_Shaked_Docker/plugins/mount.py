from typing import Iterable, List, Tuple, Callable, Any
import math
import logging

from volatility3.framework import renderers, interfaces, symbols, constants
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.framework import exceptions


MAX_STRING = 256

# mount flags - see https://elixir.bootlin.com/linux/v5.15-rc5/source/include/linux/mount.h#L26
MNT_FLAGS = {
    0x1        : "MNT_NOSUID",
    0x2        : "MNT_NODEV",
    0x4        : "MNT_NOEXEC",
    0x8        : "MNT_NOATIME",
    0x10       : "MNT_NODIRATIME",
    0x20       : "MNT_RELATIME",
    0x40       : "MNT_READONLY",
    0x80       : "MNT_NOSYMFOLLOW",
    0x100      : "MNT_SHRINKABLE",
    0x200      : "MNT_WRITE_HOLD",
    0x1000     : "MNT_SHARED",
    0x2000     : "MNT_UNBINDABLE",
    0x4000     : "MNT_INTERNAL",
    0x40000    : "MNT_LOCK_ATIME",
    0x80000    : "MNT_LOCK_NOEXEC",
    0x100000   : "MNT_LOCK_NOSUID",
    0x200000   : "MNT_LOCK_NODEV",
    0x400000   : "MNT_LOCK_READONLY",
    0x800000   : "MNT_LOCKED",
    0x1000000  : "MNT_DOOMED",
    0x2000000  : "MNT_SYNC_UMOUNT",
    0x4000000  : "MNT_MARKED",
    0x8000000  : "MNT_UMOUNT",
    0x10000000 : "MNT_CURSOR"
}

# for determining access
MNT_READONLY = 0x40 # https://elixir.bootlin.com/linux/v5.15-rc4/source/include/linux/mount.h#L32
SB_RDONLY    = 0x1  # https://elixir.bootlin.com/linux/v5.15-rc4/source/include/linux/fs.h#L1394


vollog = logging.getLogger(__name__)


class Mount(interfaces.plugins.PluginInterface):
    """Lists all mounted filesystems."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name='kernel',
                                               description='Linux kernel',
                                               architectures=['Intel32', 'Intel64']),
                requirements.PluginRequirement(name='pslist',
                                               plugin=pslist.PsList,
                                               version=(2, 0, 0)),
                requirements.BooleanRequirement(name='all',
                                                description='List all mounts',
                                                optional=True,
                                                default=False),
                requirements.ListRequirement(name='pid',
                                             description='List mounts within the mount namespace of these PIDs',
                                             element_type=int,
                                             optional=True),
                requirements.BooleanRequirement(name='sort',
                                                description='Sort mounts by mount ID',
                                                optional=True,
                                                default=False)
        ]
    
    @classmethod
    def get_all_mounts(cls,
                       context: interfaces.context.ContextInterface,
                       vmlinux_module_name: str) -> Iterable[Tuple[None, symbols.linux.extensions.mount]]:
        """Extract a list of all mounts using the mount_hashtable."""
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name
        layer = context.layers[vmlinux.layer_name]

        # kernel >= 3.13.9 uses an hlist_head instead of a list_head
        if vmlinux.has_symbol('set_mphash_entries'):
            mnt_type = 'mount'
            mount_hashtable_type = 'hlist_head'
        # in kernel >= 3.3 vfsmount was changed to mount
        elif vmlinux.has_type('mount'):
            mnt_type = 'mount'
            mount_hashtable_type = 'list_head'
        else:
            mnt_type = 'vfsmount'
            mount_hashtable_type = 'list_head'
        
        # in kernel < 3.13.9 mount_hashtable size is predefined
        if mount_hashtable_type == 'list_head':
            list_head_size = vmlinux.get_type('list_head').size
            page_size = layer.page_size
            mount_hashtable_entries = 1 << int(math.log(page_size/list_head_size, 2))
        
        # in kernel >= 3.13.9 mount_hashtable size is determined at boot time
        else:
            # m_hash_mask is the binary mask of the number of entries
            mount_hashtable_entries = vmlinux.object_from_symbol('m_hash_mask') + 1
        
        vollog.info(f'mount_hashtable entries: {mount_hashtable_entries}')

        mount_hashtable_ptr = vmlinux.object_from_symbol('mount_hashtable')
        mount_hashtable = vmlinux.object(object_type='array',
                                        offset=mount_hashtable_ptr,
                                        subtype=vmlinux.get_type(mount_hashtable_type),
                                        count=mount_hashtable_entries,
                                        absolute=True)

        # iterate through mount_hashtable
        for hash in mount_hashtable:
            # list_head - pointer to first mount is in 'next'
            if mount_hashtable_type == 'list_head':
                if not hash.next:
                    continue
                first_mount = hash.next.dereference().cast(mnt_type)
            # hlist_head - pointer to first mount is in 'first'
            elif mount_hashtable_type == 'hlist_head':
                if not hash.first:
                    continue
                first_mount = hash.first.dereference().cast(mnt_type)

            # walk linked list of mounts - the last list member may point to an invalid mount, in which case we need to stop iterating
            for mount in first_mount.mnt_hash.to_list(symbol_table + constants.BANG + mnt_type, 'mnt_hash', sentinel=False):
                # validity check - id between 0 and 10000
                if not 0 <= mount.mnt_id <= 10000:
                    break

                # validity check - devname must be printable and made of ascii characters
                try:
                    devname = utility.pointer_to_string(mount.mnt_devname, MAX_STRING)
                except exceptions.PagedInvalidAddressException:
                    break
                else:
                    if not devname or not devname.isprintable() or not all(ord(c) < 128 for c in devname):
                        break
                
                # same check with fstype
                try:
                    fs_type = utility.pointer_to_string(mount.get_mnt_sb().dereference().s_type.dereference().name, MAX_STRING)
                except exceptions.PagedInvalidAddressException:
                    break
                else:
                    if not fs_type or not fs_type.isprintable() or not all(ord(c) < 128 for c in fs_type):
                        break

                # yield None with the mount for consistency with get_mounts
                yield None, mount

    @classmethod
    def get_mounts(cls,
                   context: interfaces.context.ContextInterface,
                   vmlinux_module_name: str,
                   pid_filter: Callable[[Any], bool] = lambda pid: pid != 1
                   ) -> Iterable[Tuple[symbols.linux.extensions.task_struct, symbols.linux.extensions.mount]]:
        """Extract a list of mounts belonging to the mount namespace of the specified pids."""
        vmlinux = context.modules[vmlinux_module_name]
        symbol_table = vmlinux.symbol_table_name

        # get mount type
        if vmlinux.has_type('mount'):
            mnt_type = 'mount'
        # in kernel >= 3.3 vfsmount was changed to mount
        else:
            mnt_type = 'vfsmount'

        # set of the IDs of the seen mount namespaces
        seen_mnt_namespaces = set()

        # iterate through tasks that match the filter
        for task in pslist.PsList.list_tasks(context=context, vmlinux_module_name=vmlinux_module_name, filter_func=pid_filter):
            vollog.info(f'listing mounts for pid {task.pid}')
            try:
                mnt_ns = task.get_mnt_ns()
            except AttributeError as ex:
                vollog.error(f'No mount namespace information available: {str(ex)}')
                return
            except exceptions.PagedInvalidAddressException:
                vollog.error(f'Cannot extract mounts from pid {task.pid}')
                continue
            
            # get identifier for mnt_ns
            try:
                identifier = mnt_ns.get_inum()
            # in kernel < 3.8 mnt_namespace has no inum, track address of the mnt_namespace struct instead
            except AttributeError:
                identifier = mnt_ns.vol.offset
            
            # make sure we haven't seen this namespace yet
            if identifier in seen_mnt_namespaces:
                continue

            # add namespace to seen namespaces
            seen_mnt_namespaces.add(identifier)

            # walk mount list
            for mount in mnt_ns.list.to_list(symbol_table + constants.BANG + mnt_type, 'mnt_list'):
                yield task, mount

    @classmethod
    def get_mount_info(cls,
                       context: interfaces.context.ContextInterface,
                       vmlinux_module_name: str,
                       mount:symbols.linux.extensions.mount,
                       task: symbols.linux.extensions.task_struct) -> Tuple[int, str, str, str, str, str, str]:
        """Parse a mount and return the following tuple:
        id, devname, path, absolute_path, fstype, access, flags

        In addition to the mount, a task object needs to be passed which will be used for mount path calculation.
        """
        vmlinux = context.modules[vmlinux_module_name]

        # get mount id
        mnt_id = mount.mnt_id

        # get parent id
        try:
            parent_id = mount.get_mnt_parent().mnt_id
        except exceptions.PagedInvalidAddressException:
            parent_id = -1

        # get devname
        try:
            devname = utility.pointer_to_string(mount.mnt_devname, MAX_STRING)
        except exceptions.PagedInvalidAddressException:
            devname = ''

        # get path
        if task is not None:
            try:
                path = symbols.linux.LinuxUtilities.prepend_path(mount.get_mnt_root().dereference(), mount, task.fs.root)
            except exceptions.PagedInvalidAddressException:
                path = ''
            else:
                if path is None:
                    path = ''

        # no task supplied - use namespace agnostic method
        else:
            sb = mount.get_mnt_sb().dereference()
            s_root = sb.s_root.dereference()
            mnt_parent = mount.mnt_parent.dereference()
            mnt_root = mount.get_mnt_root().dereference()
            try:
                path = symbols.linux.LinuxUtilities._do_get_path(s_root, mnt_parent, mnt_root, mount)
            except exceptions.PagedInvalidAddressException:
                path = ''

        # get absolute path
        init_task = vmlinux.object_from_symbol(symbol_name="init_task")

        # when a mount has a master, its absolute path is the master's path
        if mount.mnt_master != 0:
            root_mnt = mount.mnt_master.dereference()
            
        # otherwise, the mount's absolute path is calculated by treating its root as belonging to the absolute fs root mount
        else:
            root_mnt = init_task.fs.root.mnt.dereference()

        dentry = mount.get_mnt_root().dereference()

        # the absolute path is calculated relative to the fs root of the init task
        try:
            absolute_path = symbols.linux.LinuxUtilities.prepend_path(dentry, root_mnt, init_task.fs.root)
        except exceptions.PagedInvalidAddressException:
            absolute_path = ''
        else:
            # if absolute path could not be calculated, the mount is independent from the fs root
            if absolute_path is None:
                absolute_path = '-'

        # get fs typee
        try:
            fs_type = utility.pointer_to_string(mount.get_mnt_sb().dereference().s_type.dereference().name, MAX_STRING)
        except exceptions.PagedInvalidAddressException:
            fs_type = ''

        # get access
        mnt_flags = mount.get_mnt_flags()
        sb_flags = mount.get_mnt_sb().s_flags
        if mnt_flags & MNT_READONLY or sb_flags & SB_RDONLY:
            access = 'RO'
        else:
            access = 'RW'

        # build string of flags
        flags = list()
        for bit_location in range(mnt_flags.vol.size * 8):
            # bit is set
            flag = mnt_flags & (1 << bit_location)
            if flag:
                # try getting flag string
                try:
                    flags.append(MNT_FLAGS[flag])
                except KeyError:
                    flags.append(f'FLAG_{hex(flag)}')
        
        return mnt_id, parent_id, devname, path, absolute_path, fs_type, access, ','.join(flags)

    def _generator(self):
        # we are listing all mounts
        if self.config.get('all', False):
            mounts = self.get_all_mounts(self.context, self.config['kernel'])

        # we are listing mounts that belong to the mount namespace of a list of pids
        else:
            pids = self.config.get('pid')
            if not pids:
                pids = [1]
            pid_filter = pslist.PsList.create_pid_filter(pids)
            mounts = self.get_mounts(self.context, self.config['kernel'], pid_filter)
        
        # sort mounts by ID
        if self.config.get('sort', False):
            mounts_by_id = {mount.mnt_id: (task, mount) for task, mount in mounts}
            ids = list(mounts_by_id.keys())
            ids.sort()
            mounts = [mounts_by_id[id] for id in ids]

        for task, mount in mounts:
            yield (0, self.get_mount_info(self.context, self.config['kernel'], mount, task=task))
    
    def run(self):
        # make sure 'all' and 'pid' aren't used together
        if self.config.get('all') and self.config.get('pid'):
            raise exceptions.PluginRequirementException('"pid" and "all" cannot be used together')

        return renderers.TreeGrid([('Mount ID', int), ('Parent ID', int), ('Devname', str), ('Path', str), ('Absolute Path', str), ('FS Type', str), ('Access', str), ('Flags', str)], self._generator())
