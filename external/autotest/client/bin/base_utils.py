"""
DO NOT import this file directly - import client/bin/utils.py,
which will mix this in

Convenience functions for use by tests or whomever.

Note that this file is mixed in by utils.py - note very carefully the
precedence order defined there
"""
import os, shutil, commands, pickle, glob
import math, re, fnmatch, logging, multiprocessing
from autotest_lib.client.common_lib import error, utils, magic


def grep(pattern, file):
    """
    This is mainly to fix the return code inversion from grep
    Also handles compressed files.

    returns 1 if the pattern is present in the file, 0 if not.
    """
    command = 'grep "%s" > /dev/null' % pattern
    ret = cat_file_to_cmd(file, command, ignore_status=True)
    return not ret


def difflist(list1, list2):
    """returns items in list2 that are not in list1"""
    diff = [];
    for x in list2:
        if x not in list1:
            diff.append(x)
    return diff


def cat_file_to_cmd(file, command, ignore_status=0, return_output=False):
    """
    equivalent to 'cat file | command' but knows to use
    zcat or bzcat if appropriate
    """
    if not os.path.isfile(file):
        raise NameError('invalid file %s to cat to command %s'
                % (file, command))

    if return_output:
        run_cmd = utils.system_output
    else:
        run_cmd = utils.system

    if magic.guess_type(file) == 'application/x-bzip2':
        cat = 'bzcat'
    elif magic.guess_type(file) == 'application/x-gzip':
        cat = 'zcat'
    else:
        cat = 'cat'
    return run_cmd('%s %s | %s' % (cat, file, command),
                                                    ignore_status=ignore_status)


def extract_tarball_to_dir(tarball, dir):
    """
    Extract a tarball to a specified directory name instead of whatever
    the top level of a tarball is - useful for versioned directory names, etc
    """
    if os.path.exists(dir):
        if os.path.isdir(dir):
            shutil.rmtree(dir)
        else:
            os.remove(dir)
    pwd = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(dir)))
    newdir = extract_tarball(tarball)
    os.rename(newdir, dir)
    os.chdir(pwd)


def extract_tarball(tarball):
    """Returns the directory extracted by the tarball."""
    extracted = cat_file_to_cmd(tarball, 'tar xvf - 2>/dev/null',
                                    return_output=True).splitlines()

    dir = None

    for line in extracted:
        if line.startswith('./'):
            line = line[2:]
        if not line or line == '.':
            continue
        topdir = line.split('/')[0]
        if os.path.isdir(topdir):
            if dir:
                assert(dir == topdir)
            else:
                dir = topdir
    if dir:
        return dir
    else:
        raise NameError('extracting tarball produced no dir')


def hash_file(filename, size=None, method="md5"):
    """
    Calculate the hash of filename.
    If size is not None, limit to first size bytes.
    Throw exception if something is wrong with filename.
    Can be also implemented with bash one-liner (assuming size%1024==0):
    dd if=filename bs=1024 count=size/1024 | sha1sum -

    @param filename: Path of the file that will have its hash calculated.
    @param method: Method used to calculate the hash. Supported methods:
            * md5
            * sha1
    @returns: Hash of the file, if something goes wrong, return None.
    """
    chunksize = 4096
    fsize = os.path.getsize(filename)

    if not size or size > fsize:
        size = fsize
    f = open(filename, 'rb')

    try:
        hash = utils.hash(method)
    except ValueError:
        logging.error("Unknown hash type %s, returning None", method)

    while size > 0:
        if chunksize > size:
            chunksize = size
        data = f.read(chunksize)
        if len(data) == 0:
            logging.debug("Nothing left to read but size=%d", size)
            break
        hash.update(data)
        size -= len(data)
    f.close()
    return hash.hexdigest()


def unmap_url_cache(cachedir, url, expected_hash, method="md5"):
    """
    Downloads a file from a URL to a cache directory. If the file is already
    at the expected position and has the expected hash, let's not download it
    again.

    @param cachedir: Directory that might hold a copy of the file we want to
            download.
    @param url: URL for the file we want to download.
    @param expected_hash: Hash string that we expect the file downloaded to
            have.
    @param method: Method used to calculate the hash string (md5, sha1).
    """
    # Let's convert cachedir to a canonical path, if it's not already
    cachedir = os.path.realpath(cachedir)
    if not os.path.isdir(cachedir):
        try:
            os.makedirs(cachedir)
        except:
            raise ValueError('Could not create cache directory %s' % cachedir)
    file_from_url = os.path.basename(url)
    file_local_path = os.path.join(cachedir, file_from_url)

    file_hash = None
    failure_counter = 0
    while not file_hash == expected_hash:
        if os.path.isfile(file_local_path):
            file_hash = hash_file(file_local_path, method)
            if file_hash == expected_hash:
                # File is already at the expected position and ready to go
                src = file_from_url
            else:
                # Let's download the package again, it's corrupted...
                logging.error("Seems that file %s is corrupted, trying to "
                              "download it again", file_from_url)
                src = url
                failure_counter += 1
        else:
            # File is not there, let's download it
            src = url
        if failure_counter > 1:
            raise EnvironmentError("Consistently failed to download the "
                                   "package %s. Aborting further download "
                                   "attempts. This might mean either the "
                                   "network connection has problems or the "
                                   "expected hash string that was determined "
                                   "for this file is wrong", file_from_url)
        file_path = utils.unmap_url(cachedir, src, cachedir)

    return file_path


def force_copy(src, dest):
    """Replace dest with a new copy of src, even if it exists"""
    if os.path.isfile(dest):
        os.remove(dest)
    if os.path.isdir(dest):
        dest = os.path.join(dest, os.path.basename(src))
    shutil.copyfile(src, dest)
    return dest


def force_link(src, dest):
    """Link src to dest, overwriting it if it exists"""
    return utils.system("ln -sf %s %s" % (src, dest))


def file_contains_pattern(file, pattern):
    """Return true if file contains the specified egrep pattern"""
    if not os.path.isfile(file):
        raise NameError('file %s does not exist' % file)
    return not utils.system('egrep -q "' + pattern + '" ' + file, ignore_status=True)


def list_grep(list, pattern):
    """True if any item in list matches the specified pattern."""
    compiled = re.compile(pattern)
    for line in list:
        match = compiled.search(line)
        if (match):
            return 1
    return 0


def get_os_vendor():
    """Try to guess what's the os vendor
    """
    if os.path.isfile('/etc/SuSE-release'):
        return 'SUSE'

    issue = '/etc/issue'

    if not os.path.isfile(issue):
        return 'Unknown'

    if file_contains_pattern(issue, 'Red Hat'):
        return 'Red Hat'
    elif file_contains_pattern(issue, 'Fedora'):
        return 'Fedora Core'
    elif file_contains_pattern(issue, 'SUSE'):
        return 'SUSE'
    elif file_contains_pattern(issue, 'Ubuntu'):
        return 'Ubuntu'
    elif file_contains_pattern(issue, 'Debian'):
        return 'Debian'
    else:
        return 'Unknown'


def get_cc():
    try:
        return os.environ['CC']
    except KeyError:
        return 'gcc'


def get_vmlinux():
    """Return the full path to vmlinux

    Ahem. This is crap. Pray harder. Bad Martin.
    """
    vmlinux = '/boot/vmlinux-%s' % utils.system_output('uname -r')
    if os.path.isfile(vmlinux):
        return vmlinux
    vmlinux = '/lib/modules/%s/build/vmlinux' % utils.system_output('uname -r')
    if os.path.isfile(vmlinux):
        return vmlinux
    return None


def get_systemmap():
    """Return the full path to System.map

    Ahem. This is crap. Pray harder. Bad Martin.
    """
    map = '/boot/System.map-%s' % utils.system_output('uname -r')
    if os.path.isfile(map):
        return map
    map = '/lib/modules/%s/build/System.map' % utils.system_output('uname -r')
    if os.path.isfile(map):
        return map
    return None


def get_modules_dir():
    """Return the modules dir for the running kernel version"""
    kernel_version = utils.system_output('uname -r')
    return '/lib/modules/%s/kernel' % kernel_version


_CPUINFO_RE = re.compile(r'^(?P<key>[^\t]*)\t*: ?(?P<value>.*)$')


def get_cpuinfo():
    """Read /proc/cpuinfo and convert to a list of dicts."""
    cpuinfo = []
    with open('/proc/cpuinfo', 'r') as f:
        cpu = {}
        for line in f:
            line = line.strip()
            if not line:
                cpuinfo.append(cpu)
                cpu = {}
                continue
            match = _CPUINFO_RE.match(line)
            cpu[match.group('key')] = match.group('value')
        if cpu:
            # cpuinfo usually ends in a blank line, so this shouldn't happen.
            cpuinfo.append(cpu)
    return cpuinfo


def get_cpu_arch():
    """Work out which CPU architecture we're running on"""
    f = open('/proc/cpuinfo', 'r')
    cpuinfo = f.readlines()
    f.close()
    if list_grep(cpuinfo, '^cpu.*(RS64|POWER3|Broadband Engine)'):
        return 'power'
    elif list_grep(cpuinfo, '^cpu.*POWER4'):
        return 'power4'
    elif list_grep(cpuinfo, '^cpu.*POWER5'):
        return 'power5'
    elif list_grep(cpuinfo, '^cpu.*POWER6'):
        return 'power6'
    elif list_grep(cpuinfo, '^cpu.*POWER7'):
        return 'power7'
    elif list_grep(cpuinfo, '^cpu.*PPC970'):
        return 'power970'
    elif list_grep(cpuinfo, 'ARM'):
        return 'arm'
    elif list_grep(cpuinfo, '^flags.*:.* lm .*'):
        return 'x86_64'
    elif list_grep(cpuinfo, 'CPU.*implementer.*0x41'):
        return 'arm'
    else:
        return 'i386'


def get_arm_soc_family():
    """Work out which ARM SoC we're running on"""
    f = open('/proc/cpuinfo', 'r')
    cpuinfo = f.readlines()
    f.close()
    if list_grep(cpuinfo, 'EXYNOS5'):
        return 'exynos5'
    elif list_grep(cpuinfo, 'Tegra'):
        return 'tegra'
    elif list_grep(cpuinfo, 'Rockchip'):
        return 'rockchip'
    return 'arm'


def get_cpu_soc_family():
    """Like get_cpu_arch, but for ARM, returns the SoC family name"""
    family = get_cpu_arch()
    if family == 'arm':
        family = get_arm_soc_family()
    return family


INTEL_UARCH_TABLE = {
    '06_1C': 'Atom',
    '06_26': 'Atom',
    '06_36': 'Atom',
    '06_4C': 'Braswell',
    '06_3D': 'Broadwell',
    '06_0D': 'Dothan',
    '06_3A': 'IvyBridge',
    '06_3E': 'IvyBridge',
    '06_3C': 'Haswell',
    '06_3F': 'Haswell',
    '06_45': 'Haswell',
    '06_46': 'Haswell',
    '06_0F': 'Merom',
    '06_16': 'Merom',
    '06_17': 'Nehalem',
    '06_1A': 'Nehalem',
    '06_1D': 'Nehalem',
    '06_1E': 'Nehalem',
    '06_1F': 'Nehalem',
    '06_2E': 'Nehalem',
    '06_2A': 'SandyBridge',
    '06_2D': 'SandyBridge',
    '06_4E': 'Skylake',
    '0F_03': 'Prescott',
    '0F_04': 'Prescott',
    '0F_06': 'Presler',
    '06_25': 'Westmere',
    '06_2C': 'Westmere',
    '06_2F': 'Westmere',
}


def get_intel_cpu_uarch(numeric=False):
    """Return the Intel microarchitecture we're running on, or None.

    Returns None if this is not an Intel CPU. Returns the family and model as
    underscore-separated hex (per Intel manual convention) if the uarch is not
    known, or if numeric is True.
    """
    if not get_current_kernel_arch().startswith('x86'):
        return None
    cpuinfo = get_cpuinfo()[0]
    if cpuinfo['vendor_id'] != 'GenuineIntel':
        return None
    family_model = '%02X_%02X' % (int(cpuinfo['cpu family']),
                                  int(cpuinfo['model']))
    if numeric:
        return family_model
    return INTEL_UARCH_TABLE.get(family_model, family_model)


def get_current_kernel_arch():
    """Get the machine architecture, now just a wrap of 'uname -m'."""
    return os.popen('uname -m').read().rstrip()


def get_file_arch(filename):
    # -L means follow symlinks
    file_data = utils.system_output('file -L ' + filename)
    if file_data.count('80386'):
        return 'i386'
    return None


def count_cpus():
    """number of CPUs in the local machine according to /proc/cpuinfo"""
    try:
       return multiprocessing.cpu_count()
    except Exception as e:
       logging.exception('can not get cpu count from'
                        ' multiprocessing.cpu_count()')
    cpuinfo = get_cpuinfo()
    # Returns at least one cpu. Check comment #1 in crosbug.com/p/9582.
    return len(cpuinfo) or 1


def cpu_online_map():
    """
    Check out the available cpu online map
    """
    cpuinfo = get_cpuinfo()
    cpus = []
    for cpu in cpuinfo:
        cpus.append(cpu['processor'])  # grab cpu number
    return cpus


def get_cpu_family():
    cpuinfo = get_cpuinfo()[0]
    return int(cpuinfo['cpu_family'])


def get_cpu_vendor():
    cpuinfo = get_cpuinfo()
    vendors = [cpu['vendor_id'] for cpu in cpuinfo]
    for v in vendors[1:]:
        if v != vendors[0]:
            raise error.TestError('multiple cpu vendors found: ' + str(vendors))
    return vendors[0]


def probe_cpus():
    """
    This routine returns a list of cpu devices found under
    /sys/devices/system/cpu.
    """
    cmd = 'find /sys/devices/system/cpu/ -maxdepth 1 -type d -name cpu*'
    return utils.system_output(cmd).splitlines()


# Returns total memory in kb
def read_from_meminfo(key):
    meminfo = utils.system_output('grep %s /proc/meminfo' % key)
    return int(re.search(r'\d+', meminfo).group(0))


def memtotal():
    return read_from_meminfo('MemTotal')


def freememtotal():
    return read_from_meminfo('MemFree')

def usable_memtotal():
    # Reserved 5% for OS use
    return int(read_from_meminfo('MemFree') * 0.95)


def rounded_memtotal():
    # Get total of all physical mem, in kbytes
    usable_kbytes = memtotal()
    # usable_kbytes is system's usable DRAM in kbytes,
    #   as reported by memtotal() from device /proc/meminfo memtotal
    #   after Linux deducts 1.5% to 5.1% for system table overhead
    # Undo the unknown actual deduction by rounding up
    #   to next small multiple of a big power-of-two
    #   eg  12GB - 5.1% gets rounded back up to 12GB
    mindeduct = 0.015  # 1.5 percent
    maxdeduct = 0.055  # 5.5 percent
    # deduction range 1.5% .. 5.5% supports physical mem sizes
    #    6GB .. 12GB in steps of .5GB
    #   12GB .. 24GB in steps of 1 GB
    #   24GB .. 48GB in steps of 2 GB ...
    # Finer granularity in physical mem sizes would require
    #   tighter spread between min and max possible deductions

    # increase mem size by at least min deduction, without rounding
    min_kbytes = int(usable_kbytes / (1.0 - mindeduct))
    # increase mem size further by 2**n rounding, by 0..roundKb or more
    round_kbytes = int(usable_kbytes / (1.0 - maxdeduct)) - min_kbytes
    # find least binary roundup 2**n that covers worst-cast roundKb
    mod2n = 1 << int(math.ceil(math.log(round_kbytes, 2)))
    # have round_kbytes <= mod2n < round_kbytes*2
    # round min_kbytes up to next multiple of mod2n
    phys_kbytes = min_kbytes + mod2n - 1
    phys_kbytes = phys_kbytes - (phys_kbytes % mod2n)  # clear low bits
    return phys_kbytes


def sysctl(key, value=None):
    """Generic implementation of sysctl, to read and write.

    @param key: A location under /proc/sys
    @param value: If not None, a value to write into the sysctl.

    @return The single-line sysctl value as a string.
    """
    path = '/proc/sys/%s' % key
    if value is not None:
        utils.write_one_line(path, str(value))
    return utils.read_one_line(path)


def sysctl_kernel(key, value=None):
    """(Very) partial implementation of sysctl, for kernel params"""
    if value is not None:
        # write
        utils.write_one_line('/proc/sys/kernel/%s' % key, str(value))
    else:
        # read
        out = utils.read_one_line('/proc/sys/kernel/%s' % key)
        return int(re.search(r'\d+', out).group(0))


def _convert_exit_status(sts):
    if os.WIFSIGNALED(sts):
        return -os.WTERMSIG(sts)
    elif os.WIFEXITED(sts):
        return os.WEXITSTATUS(sts)
    else:
        # impossible?
        raise RuntimeError("Unknown exit status %d!" % sts)


def where_art_thy_filehandles():
    """Dump the current list of filehandles"""
    os.system("ls -l /proc/%d/fd >> /dev/tty" % os.getpid())


def print_to_tty(string):
    """Output string straight to the tty"""
    open('/dev/tty', 'w').write(string + '\n')


def dump_object(object):
    """Dump an object's attributes and methods

    kind of like dir()
    """
    for item in object.__dict__.iteritems():
        print item
        try:
            (key, value) = item
            dump_object(value)
        except:
            continue


def environ(env_key):
    """return the requested environment variable, or '' if unset"""
    if (os.environ.has_key(env_key)):
        return os.environ[env_key]
    else:
        return ''


def prepend_path(newpath, oldpath):
    """prepend newpath to oldpath"""
    if (oldpath):
        return newpath + ':' + oldpath
    else:
        return newpath


def append_path(oldpath, newpath):
    """append newpath to oldpath"""
    if (oldpath):
        return oldpath + ':' + newpath
    else:
        return newpath


_TIME_OUTPUT_RE = re.compile(
        r'([\d\.]*)user ([\d\.]*)system '
        r'(\d*):([\d\.]*)elapsed (\d*)%CPU')


def avgtime_print(dir):
    """ Calculate some benchmarking statistics.
        Input is a directory containing a file called 'time'.
        File contains one-per-line results of /usr/bin/time.
        Output is average Elapsed, User, and System time in seconds,
          and average CPU percentage.
    """
    user = system = elapsed = cpu = count = 0
    with open(dir + "/time") as f:
        for line in f:
            try:
                m = _TIME_OUTPUT_RE.match(line);
                user += float(m.group(1))
                system += float(m.group(2))
                elapsed += (float(m.group(3)) * 60) + float(m.group(4))
                cpu += float(m.group(5))
                count += 1
            except:
                raise ValueError("badly formatted times")

    return "Elapsed: %0.2fs User: %0.2fs System: %0.2fs CPU: %0.0f%%" % \
          (elapsed / count, user / count, system / count, cpu / count)


def to_seconds(time_string):
    """Converts a string in M+:SS.SS format to S+.SS"""
    elts = time_string.split(':')
    if len(elts) == 1:
        return time_string
    return str(int(elts[0]) * 60 + float(elts[1]))


_TIME_OUTPUT_RE_2 = re.compile(r'(.*?)user (.*?)system (.*?)elapsed')


def extract_all_time_results(results_string):
    """Extract user, system, and elapsed times into a list of tuples"""
    results = []
    for result in _TIME_OUTPUT_RE_2.findall(results_string):
        results.append(tuple([to_seconds(elt) for elt in result]))
    return results


def running_config():
    """
    Return path of config file of the currently running kernel
    """
    version = utils.system_output('uname -r')
    for config in ('/proc/config.gz', \
                   '/boot/config-%s' % version,
                   '/lib/modules/%s/build/.config' % version):
        if os.path.isfile(config):
            return config
    return None


def check_for_kernel_feature(feature):
    config = running_config()

    if not config:
        raise TypeError("Can't find kernel config file")

    if magic.guess_type(config) == 'application/x-gzip':
        grep = 'zgrep'
    else:
        grep = 'grep'
    grep += ' ^CONFIG_%s= %s' % (feature, config)

    if not utils.system_output(grep, ignore_status=True):
        raise ValueError("Kernel doesn't have a %s feature" % (feature))


def check_glibc_ver(ver):
    glibc_ver = commands.getoutput('ldd --version').splitlines()[0]
    glibc_ver = re.search(r'(\d+\.\d+(\.\d+)?)', glibc_ver).group()
    if utils.compare_versions(glibc_ver, ver) == -1:
        raise error.TestError("Glibc too old (%s). Glibc >= %s is needed." %
                              (glibc_ver, ver))

def check_kernel_ver(ver):
    kernel_ver = utils.system_output('uname -r')
    kv_tmp = re.split(r'[-]', kernel_ver)[0:3]
    # In compare_versions, if v1 < v2, return value == -1
    if utils.compare_versions(kv_tmp[0], ver) == -1:
        raise error.TestError("Kernel too old (%s). Kernel > %s is needed." %
                              (kernel_ver, ver))


def human_format(number):
    # Convert number to kilo / mega / giga format.
    if number < 1024:
        return "%d" % number
    kilo = float(number) / 1024.0
    if kilo < 1024:
        return "%.2fk" % kilo
    meg = kilo / 1024.0
    if meg < 1024:
        return "%.2fM" % meg
    gig = meg / 1024.0
    return "%.2fG" % gig


def numa_nodes():
    node_paths = glob.glob('/sys/devices/system/node/node*')
    nodes = [int(re.sub(r'.*node(\d+)', r'\1', x)) for x in node_paths]
    return (sorted(nodes))


def node_size():
    nodes = max(len(numa_nodes()), 1)
    return ((memtotal() * 1024) / nodes)


def pickle_load(filename):
    return pickle.load(open(filename, 'r'))


# Return the kernel version and build timestamp.
def running_os_release():
    return os.uname()[2:4]


def running_os_ident():
    (version, timestamp) = running_os_release()
    return version + '::' + timestamp


def running_os_full_version():
    (version, timestamp) = running_os_release()
    return version


# much like find . -name 'pattern'
def locate(pattern, root=os.getcwd()):
    for path, dirs, files in os.walk(root):
        for f in files:
            if fnmatch.fnmatch(f, pattern):
                yield os.path.abspath(os.path.join(path, f))


def freespace(path):
    """Return the disk free space, in bytes"""
    s = os.statvfs(path)
    return s.f_bavail * s.f_bsize


def disk_block_size(path):
    """Return the disk block size, in bytes"""
    return os.statvfs(path).f_bsize


_DISK_PARTITION_3_RE = re.compile(r'^(/dev/hd[a-z]+)3', re.M)

def get_disks():
    df_output = utils.system_output('df')
    return _DISK_PARTITION_3_RE.findall(df_output)


def get_disk_size(disk_name):
    """
    Return size of disk in byte. Return 0 in Error Case

    @param disk_name: disk name to find size
    """
    device = os.path.basename(disk_name)
    for line in file('/proc/partitions'):
        try:
            _, _, blocks, name = re.split(r' +', line.strip())
        except ValueError:
            continue
        if name == device:
            return 1024 * int(blocks)
    return 0


def get_disk_size_gb(disk_name):
    """
    Return size of disk in GB (10^9). Return 0 in Error Case

    @param disk_name: disk name to find size
    """
    return int(get_disk_size(disk_name) / (10.0 ** 9) + 0.5)


def get_disk_model(disk_name):
    """
    Return model name for internal storage device

    @param disk_name: disk name to find model
    """
    cmd1 = 'udevadm info --query=property --name=%s' % disk_name
    cmd2 = 'grep -E "ID_(NAME|MODEL)="'
    cmd3 = 'cut -f 2 -d"="'
    cmd = ' | '.join([cmd1, cmd2, cmd3])
    return utils.system_output(cmd)


_DISK_DEV_RE = re.compile(r'/dev/sd[a-z]|/dev/mmcblk[0-9]*')


def get_disk_from_filename(filename):
    """
    Return the disk device the filename is on.
    If the file is on tmpfs or other special file systems,
    return None.

    @param filename: name of file, full path.
    """

    if not os.path.exists(filename):
        raise error.TestError('file %s missing' % filename)

    if filename[0] != '/':
        raise error.TestError('This code works only with full path')

    m = _DISK_DEV_RE.match(filename)
    while not m:
        if filename[0] != '/':
            return None
        if filename == '/dev/root':
            cmd = 'rootdev -d -s'
        elif filename.startswith('/dev/mapper'):
            cmd = 'dmsetup table "%s"' % os.path.basename(filename)
            dmsetup_output = utils.system_output(cmd).split(' ')
            if dmsetup_output[2] == 'verity':
                maj_min = dmsetup_output[4]
            elif dmsetup_output[2] == 'crypt':
                maj_min = dmsetup_output[6]
            cmd = 'realpath "/dev/block/%s"' % maj_min
        elif filename.startswith('/dev/loop'):
            cmd = 'losetup -O BACK-FILE "%s" | tail -1' % filename
        else:
            cmd = 'df "%s" | tail -1 | cut -f 1 -d" "' % filename
        filename = utils.system_output(cmd)
        m = _DISK_DEV_RE.match(filename)
    return m.group(0)


def get_disk_firmware_version(disk_name):
    """
    Return firmware version for internal storage device. (empty string for eMMC)

    @param disk_name: disk name to find model
    """
    cmd1 = 'udevadm info --query=property --name=%s' % disk_name
    cmd2 = 'grep -E "ID_REVISION="'
    cmd3 = 'cut -f 2 -d"="'
    cmd = ' | '.join([cmd1, cmd2, cmd3])
    return utils.system_output(cmd)


def is_disk_scsi(disk_name):
    """
    Return true if disk is a scsi device, return false otherwise

    @param disk_name: disk name check
    """
    return re.match('/dev/sd[a-z]+', disk_name)


def is_disk_harddisk(disk_name):
    """
    Return true if disk is a harddisk, return false otherwise

    @param disk_name: disk name check
    """
    cmd1 = 'udevadm info --query=property --name=%s' % disk_name
    cmd2 = 'grep -E "ID_ATA_ROTATION_RATE_RPM="'
    cmd3 = 'cut -f 2 -d"="'
    cmd = ' | '.join([cmd1, cmd2, cmd3])

    rtt = utils.system_output(cmd)

    # eMMC will not have this field; rtt == ''
    # SSD will have zero rotation rate; rtt == '0'
    # For harddisk rtt > 0
    return rtt and int(rtt) > 0


def verify_hdparm_feature(disk_name, feature):
    """
    Check for feature support for SCSI disk using hdparm

    @param disk_name: target disk
    @param feature: hdparm output string of the feature
    """
    cmd = 'hdparm -I %s | grep -q "%s"' % (disk_name, feature)
    ret = utils.system(cmd, ignore_status=True)
    if ret == 0:
        return True
    elif ret == 1:
        return False
    else:
        raise error.TestFail('Error running command %s' % cmd)


def get_storage_error_msg(disk_name, reason):
    """
    Get Error message for storage test which include disk model.
    and also include the firmware version for the SCSI disk

    @param disk_name: target disk
    @param reason: Reason of the error.
    """

    msg = reason

    model = get_disk_model(disk_name)
    msg += ' Disk model: %s' % model

    if is_disk_scsi(disk_name):
        fw = get_disk_firmware_version(disk_name)
        msg += ' firmware: %s' % fw

    return msg


def load_module(module_name, params=None):
    # Checks if a module has already been loaded
    if module_is_loaded(module_name):
        return False

    cmd = '/sbin/modprobe ' + module_name
    if params:
        cmd += ' ' + params
    utils.system(cmd)
    return True


def unload_module(module_name):
    """
    Removes a module. Handles dependencies. If even then it's not possible
    to remove one of the modules, it will trhow an error.CmdError exception.

    @param module_name: Name of the module we want to remove.
    """
    l_raw = utils.system_output("/bin/lsmod").splitlines()
    lsmod = [x for x in l_raw if x.split()[0] == module_name]
    if len(lsmod) > 0:
        line_parts = lsmod[0].split()
        if len(line_parts) == 4:
            submodules = line_parts[3].split(",")
            for submodule in submodules:
                unload_module(submodule)
        utils.system("/sbin/modprobe -r %s" % module_name)
        logging.info("Module %s unloaded", module_name)
    else:
        logging.info("Module %s is already unloaded", module_name)


def module_is_loaded(module_name):
    module_name = module_name.replace('-', '_')
    modules = utils.system_output('/bin/lsmod').splitlines()
    for module in modules:
        if module.startswith(module_name) and module[len(module_name)] == ' ':
            return True
    return False


def get_loaded_modules():
    lsmod_output = utils.system_output('/bin/lsmod').splitlines()[1:]
    return [line.split(None, 1)[0] for line in lsmod_output]


def get_huge_page_size():
    output = utils.system_output('grep Hugepagesize /proc/meminfo')
    return int(output.split()[1]) # Assumes units always in kB. :(


def get_num_huge_pages():
    raw_hugepages = utils.system_output('/sbin/sysctl vm.nr_hugepages')
    return int(raw_hugepages.split()[2])


def set_num_huge_pages(num):
    utils.system('/sbin/sysctl vm.nr_hugepages=%d' % num)


def ping_default_gateway():
    """Ping the default gateway."""

    network = open('/etc/sysconfig/network')
    m = re.search('GATEWAY=(\S+)', network.read())

    if m:
        gw = m.group(1)
        cmd = 'ping %s -c 5 > /dev/null' % gw
        return utils.system(cmd, ignore_status=True)

    raise error.TestError('Unable to find default gateway')


def drop_caches():
    """Writes back all dirty pages to disk and clears all the caches."""
    utils.system("sync")
    # We ignore failures here as this will fail on 2.6.11 kernels.
    utils.system("echo 3 > /proc/sys/vm/drop_caches", ignore_status=True)


def process_is_alive(name_pattern):
    """
    'pgrep name' misses all python processes and also long process names.
    'pgrep -f name' gets all shell commands with name in args.
    So look only for command whose initial pathname ends with name.
    Name itself is an egrep pattern, so it can use | etc for variations.
    """
    return utils.system("pgrep -f '^([^ /]*/)*(%s)([ ]|$)'" % name_pattern,
                        ignore_status=True) == 0


def get_hwclock_seconds(utc=True):
    """
    Return the hardware clock in seconds as a floating point value.
    Use Coordinated Universal Time if utc is True, local time otherwise.
    Raise a ValueError if unable to read the hardware clock.
    """
    cmd = '/sbin/hwclock --debug'
    if utc:
        cmd += ' --utc'
    hwclock_output = utils.system_output(cmd, ignore_status=True)
    match = re.search(r'= ([0-9]+) seconds since .+ (-?[0-9.]+) seconds$',
                      hwclock_output, re.DOTALL)
    if match:
        seconds = int(match.group(1)) + float(match.group(2))
        logging.debug('hwclock seconds = %f', seconds)
        return seconds

    raise ValueError('Unable to read the hardware clock -- ' +
                     hwclock_output)


def set_wake_alarm(alarm_time):
    """
    Set the hardware RTC-based wake alarm to 'alarm_time'.
    """
    utils.write_one_line('/sys/class/rtc/rtc0/wakealarm', str(alarm_time))


def set_power_state(state):
    """
    Set the system power state to 'state'.
    """
    utils.write_one_line('/sys/power/state', state)


def standby():
    """
    Power-on suspend (S1)
    """
    set_power_state('standby')


def suspend_to_ram():
    """
    Suspend the system to RAM (S3)
    """
    set_power_state('mem')


def suspend_to_disk():
    """
    Suspend the system to disk (S4)
    """
    set_power_state('disk')
