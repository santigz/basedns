import subprocess
import psutil


class NamedCheckConfError(Exception):
    pass

class NamedCheckZoneError(Exception):
    pass

class NamedReloadError(Exception):
    pass


class NamedManager(object):

    @classmethod
    def check_and_run(cls, origin, zone_file) -> None:
        NamedManager.named_checkconf()
        NamedManager.named_checkzone(origin, zone_file)
        NamedManager.run()

    @classmethod
    def run(cls) -> None:
        if not NamedManager.named_pid():
            subprocess.run(['named'], timeout=5)

    @classmethod
    def reload(cls) -> str:
        proc = subprocess.run(['rndc', 'reload'],
                              timeout=15,
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.STDOUT,
                              text=True)
        if proc.returncode == 0:
            return proc.stdout
        else:
            raise NamedReloadError(proc.stdout)

    @classmethod
    def named_pid(cls):
        for process in psutil.process_iter(['name', 'pid']):
            try:
                if process.info['name'] == 'named':
                    return process.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    @classmethod
    def named_checkconf(cls) -> str:
        '''
        Runs named-checkconf.
        Returns a tuple (success, msg):
        - success = {True|False}
        - msg: message in case of error
        '''
        proc = subprocess.run(['named-checkconf'], 
                              timeout=5,
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.STDOUT,
                              text=True)
        if proc.returncode == 0:
            return proc.stdout
        else:
            raise NamedCheckConfError(proc.stdout)

    @classmethod
    def named_checkzone(cls, origin, zone_file) -> str:
        # named-checkzone -k fail ensures zone names are strictly checked
        proc = subprocess.run(['named-checkzone', '-k', 'fail', origin, zone_file], 
                              timeout=5,
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.STDOUT,
                              text=True)
        if proc.returncode == 0:
            return proc.stdout
        else:
            raise NamedCheckZoneError(proc.stdout)

