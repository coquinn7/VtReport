import virustotal
from pathlib import Path
import volatility.debug as debug
import volatility.obj as obj
import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.common as common


class VtReport(common.AbstractWindowsCommand):
    """Extract an executable file from a process' address space and get VirusTotal report"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('DUMP', short_option='D', default=None,
                          help='Directory to dump executable file', cache_invalidator=False)
        config.add_option('PID', short_option='p', default=None,
                          help='Dump executable file from this process', action='store', type='str')
        config.add_option('APIKEY', short_option='a', default=None,
                          help='VirusTotal API Key', action='store', type='str')

    def dump_pe(self, space, base, dump_file):
        """
        Dump a PE from an address space and return path to file
        :param space: Address space
        :param base: PE base address
        :param dump_file: Dumped filename
        :return: Path of dumped file
        """
        if not Path(self._config.DUMP).exists():
            Path(self._config.DUMP).mkdir(parents=True)

        out_file = Path(self._config.DUMP).joinpath(dump_file)
        # Create DOS header at base address
        # Offset = process PEB Image Base Address
        # Vm = process space
        pe_file = obj.Object("_IMAGE_DOS_HEADER", offset=base, vm=space)

        try:
            with out_file.open('wb') as fh:
                for offset, code in pe_file.get_image():
                    fh.seek(offset)
                    fh.write(code)
        except Exception as e:
            debug.error(e)
        else:
            return out_file

    def get_pid(self, tasks):
        """
        Isolate a process based on user supplied PID
        :param tasks: processes in address space
        :return: PID specified at CLI
        """
        if self._config.PID is None:
            debug.error('Please provide a PID')
        try:
            # cast user supplied PID as int to validate input
            pid = int(self._config.PID)
        except ValueError:
            debug.error('Invalid PID: {}'.format(self._config.PID))
        else:
            found = False
            for task in tasks:
                if str(task.UniqueProcessId) == str(pid):
                    found = True
                    return task
            if not found:
                debug.error('PID: {} not found'.format(self._config.PID))

    def get_report(self, in_file):
        """
        Submit dumped PE to VT and return report
        :param in_file: Path to dumped PE
        :return: VirusTotal Report
        """
        if self._config.APIKEY is None:
            debug.error('Please provide a VirusTotal API Key')
        vt = virustotal.VirusTotal(self._config.APIKEY)
        try:
            report = vt.scan(in_file)
        except Exception as e:
            debug.error(e)
        else:
            # wait for VT to scan the file
            report.join()
            assert report.done is True
            return report

    def calculate(self):
        """
        do the work, return the vt report object
        :return: VT report object
        """
        addr_space = utils.load_as(self._config)
        task = self.get_pid(win32.tasks.pslist(addr_space))
        task_space = task.get_process_address_space()

        if task_space is None:
            debug.error('Can\'t find process address space for process: {}'.format(task.ImageFileName))

        elif task.Peb is None:
            debug.error('PEB is not available for process {}'.format(task.ImageFileName))

        elif task_space.vtop(task.Peb.ImageBaseAddress) is None:
            debug.error('ImageBaseAddress is not available for process {}'.format(task.ImageFileName))

        else:
            dump_file = 'PID-{}-{}'.format(str(task.UniqueProcessId), str(task.ImageFileName).replace('.exe', ''))
            # extract file and return path
            dump_path = self.dump_pe(task_space, task.Peb.ImageBaseAddress, dump_file)
            report = self.get_report(str(dump_path))
            #  report will be the data in render_text method
            return report

    def render_text(self, outfd, data):
        """
        write VT report details to console
        :param outfd: text to write
        :param data: VT report object
        :return: nothing
        """
        outfd.write('\n{:*^100}\n'.format(' VirusTotal Report '))
        outfd.write('\nPermalink: {}\n'.format(data.permalink))
        outfd.write('''
Antivirus hits: {}
Total AV Engines: {}
MD5: {}
SHA1: {}
SHA256: {}
    '''.format(data.positives, data.total, data.md5, data.sha1, data.sha256))

        for antivirus, malware in data:
            if malware is not None:
                outfd.write('''
Antivirus: {}
Antivirus version: {}
Antivirus update: {}
Malware: {}
                '''.format(antivirus[0], antivirus[1], antivirus[2], malware))


