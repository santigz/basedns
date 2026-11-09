import base64
import ipaddress
import dns.exception
import dns.resolver
import dns.zone
import hashlib
import hmac
import logging
import os
import requests
import secrets
import shutil
import tarfile
import re

from datetime import datetime, timedelta
from typing import Dict
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

from .named_manager import NamedManager, NamedCheckConfError, NamedCheckZoneError, NamedReloadError

# Bind globals
BIND_DIR = '/etc/bind/'
NAMED_INITIALIZATION_TAG = 'named_initialized: true'
MAIN_ZONE_FILE = '/etc/bind/main-zone'
NAMED_CONF_LOCAL_FILE = '/etc/bind/named.conf.local'
CUSTOM_RRS_FILE = '/etc/bind/custom-records'
USER_ZONES_DIR = '/etc/bind/user-zones/'
USER_TOKENS_DIR = '/etc/bind/user-tokens/'
BACKUPS_DIR = '/etc/bind-backups/'

# Templates globals
TEMPLATES_DIR = 'templates/bind/'
ZONEFILE_TEMPLATE = 'main-zone.j2'
NAMED_CONF_TEMPLATE = 'named.conf.j2'
NAMED_CONF_OPTIONS_TEMPLATE = 'named.conf.options.j2'
NAMED_CONF_LOCAL_TEMPLATE = 'named.conf.local.j2'
NAMED_CONF_RNDC_TEMPLATE = 'named.conf.rndc.j2'
RNDC_CONF_TEMPLATE = 'rndc.conf.j2'
USER_ZONE_TEMPLATE = 'user-zone.j2'

PUBLIC_IP_REFRESH = 1 # Hours to refresh the public IP
USER_TOKEN_LENGTH = 16

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class PublicIpNotFound(Exception):
    pass

class BadZoneFile(Exception):
    pass

class ZoneFileCheckError(Exception):
    pass

class ZoneCreationError(Exception):
    pass

class RecordUpdateError(Exception):
    pass





class ZoneManager(object):
    
    def __init__(self, origin) -> None:
        self._public_ip = None
        self._public_ip_last_date = datetime.now() - timedelta(hours=PUBLIC_IP_REFRESH*2)
        self.origin = origin
        if not self.origin.endswith('.'):
            self.origin += '.'
        logger.info(f'ORIGIN {self.origin}')
        self.jinja_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
        named_conf = Path(BIND_DIR) / 'named.conf'
        if not named_conf.exists() or NAMED_INITIALIZATION_TAG not in named_conf.read_text():
            logger.info('Named configuration is uninitialized. Resetting named configuration.')
            self.delete_all_named_config()
            Path(USER_ZONES_DIR).mkdir(parents=True, exist_ok=True)
            Path(USER_TOKENS_DIR).mkdir(parents=True, exist_ok=True)
            self.full_reset()
        else:
            Path(USER_ZONES_DIR).mkdir(parents=True, exist_ok=True)
            Path(USER_TOKENS_DIR).mkdir(parents=True, exist_ok=True)

        bind_failed = False
        try:
            NamedManager.check_and_run(self.origin, MAIN_ZONE_FILE)
            logger.info('Bind passed checks and is running.')
        except NamedCheckConfError as e:
            bind_failed = True
            logger.error(f'ERROR in named-checkconf!!!!!!\n{e}')
        except NamedCheckZoneError as e:
            bind_failed = True
            contents = Path(MAIN_ZONE_FILE).read_text() if Path(MAIN_ZONE_FILE).exists() else '<file not found>'
            logger.error(f'Main zone file:\n{contents}')
            logger.error(f'ERROR in named-checkzone in main zone!!!!!!\n{e}')
        if bind_failed:
            try:
                logger.info('Doing a backup and full Bind reset. All previous config is removed.')
                self.backup()
                self.full_reset()
                logger.info('Trying to start bind after reset.')
                NamedManager.check_and_run(self.origin, MAIN_ZONE_FILE)
            except Exception:
                logger.error(f'Failed resetting. Can not continue Bind.')
                raise

    @property
    def public_ip(self) -> str | None:
        delta = datetime.now() - self._public_ip_last_date
        if not self._public_ip or delta > timedelta(hours=PUBLIC_IP_REFRESH):
            try:
                self._public_ip = self.get_public_ip()
                self._public_ip_last_date = datetime.now()
            except PublicIpNotFound as e:
                logger.error(f'Could not find public IP: {e}')
        return self._public_ip

    def full_reset(self) -> None:
        self.write_template(NAMED_CONF_TEMPLATE, BIND_DIR, {})
        self.write_template(NAMED_CONF_OPTIONS_TEMPLATE, BIND_DIR, {})
        self.reset_rndc()
        self.reset_main_zone()
        self.reset_all_user_zonefiles()
        self.reset_named_conf_local()

    # def load_root_zone(self) -> None:
    #     self.root = dns.zone.from_file(MAIN_ZONE_FILE, relativize=False)

    # def check_zone_file_dnspython(self, zone_file: str, origin: str):
    #     try:
    #         logger.info(f'Checking zone file {zone_file}')
    #         zone = dns.zone.from_file(zone_file, origin=origin)  # Change the origin accordingly
    #         for name, node in zone.nodes.items():
    #             print(f"Records for {name}:")
    #             for record in node.rdatas:
    #                 logger.debug(record)
    #     except FileNotFoundError as e:
    #         logger.error(f'File not found: {zone_file}')
    #     except dns.exception.DNSException as e:
    #         logger.error(f"Error reading zone file: {e}")

    def user_zone_origin(self, username):
        return username + '.' + self.origin

    def get_user_zonefile(self, username: str) -> str:
        zonefile = Path(USER_ZONES_DIR) / username
        if not zonefile.exists():
            logger.info(f'Zone file does not exist for user: {username}')
            self.reset_user_zonefile(username)
            self.reset_named_conf_local()
        return zonefile.read_text()

    # def zonefile_to_json(self, zonefile: str):
    #     zone = dns.zone.from_file(zonefile, relativize=False)
    #     for (name, node) in zone.items():
    #         print(name)
    #         for rdset in node:
    #             type = rdset.rdtype
    #             print(f'{dns.rdatatype.to_text(rdset.rdtype)}')
    #             for rr in rdset:
    #                 print(f'rr {rr}')
    #         print()

    def find_user_list(self):
        return [f.name for f in Path(USER_ZONES_DIR).iterdir() if f.is_file()]

    def reset_main_zone(self):
        user_list = self.find_user_list()
        self.reset_zonefile(self.origin, ZONEFILE_TEMPLATE, MAIN_ZONE_FILE, user_list)

    def set_user_zonefile(self, username: str, zone_data: str) -> None:
        origin = username + '.' + self.origin
        tmp_zonefile = Path(USER_ZONES_DIR) / Path(username + '.tmp')
        try:
            tmp_zonefile.write_text(zone_data)
            msg = NamedManager.named_checkzone(origin, tmp_zonefile)
        except OSError:
            tmp_zonefile.unlink(missing_ok=True)
            raise Exception('Internal file system error.')
        except NamedCheckZoneError as e:
            tmp_zonefile.unlink(missing_ok=True)
            raise BadZoneFile(e)
        except Exception:
            tmp_zonefile.unlink(missing_ok=True)
            raise ZoneFileCheckError('Unknown error checking the zone.')
        zonefile = Path(USER_ZONES_DIR) / username
        try:
            self.replace_zone_if_reloads(tmp_zonefile, username)
        except NamedReloadError as e:
            raise BadZoneFile('Zone seems OK but there was an error reloading Bind.')

    def replace_zone_if_reloads(self, tmp_zonefile: Path, username: str) -> None:
        zonefile = Path(USER_ZONES_DIR) / username
        zonefile_backup = zonefile.with_suffix('.orig')
        if zonefile.exists():
            shutil.copy2(zonefile, zonefile_backup)
        tmp_zonefile.replace(zonefile)
        try:
            NamedManager.reload()
            zonefile_backup.unlink(missing_ok=True)
        except NamedReloadError:
            contents = zonefile.read_text()
            logger.error(f'Passed named-checkzone but reload error for user {username}:\n{contents}')
            if zonefile_backup.exists():
                shutil.copy2(zonefile_backup, zonefile)
                zonefile_backup.unlink(missing_ok=True)
            else:
                zonefile.unlink(missing_ok=True)
            try:
                NamedManager.reload()
            except NamedReloadError:
                logger.error(f'VERY BAD SITUATION: failed reverting a reload error for user {username}. ******')
                raise
            raise

    def reset_user_zonefile(self, username: str) -> str:
        origin = username + '.' + self.origin
        zonefile = Path(USER_ZONES_DIR) / username
        zone = self.reset_zonefile(origin, USER_ZONE_TEMPLATE, zonefile)
        if NamedManager.named_pid():
            NamedManager.reload()
        return zone

    def custom_records(self):
        try:
            return Path(CUSTOM_RRS_FILE).read_text()
        except:
            return ''

    def reset_zonefile(self, origin: str, zone_template: str, zonefile: str|Path, user_list: list[str] | None = None) -> str:
        if user_list is None:
            user_list = []
        logger.info(f'Resetting zone {zonefile}')
        if not self.public_ip:
            raise ZoneCreationError('No public IP')
        try:
            template = self.jinja_env.get_template(zone_template)
            # TODO: get custom records only for main zone, not for all
            data = {
                    'origin': origin,
                    'ns_ip': self.public_ip,
                    'user_list': user_list,
                    'custom_records': self.custom_records(),
                    }
            zone = template.render(data)
            Path(zonefile).write_text(zone)
            return zone
        except:
            raise ZoneCreationError()


    def reset_named_conf_local(self) -> None:
        '''Reads all user names from `users_dir` and resets bind config config for their zones.'''
        user_list = self.find_user_list()
        # self.reset_bind_conf_users(NAMED_CONF_LOCAL_TEMPLATE, NAMED_CONF_LOCAL_FILE, user_list)
        self.write_template(NAMED_CONF_LOCAL_TEMPLATE, 
                            BIND_DIR, 
                            { 
                                'origin': self.origin, 
                                'user_list': user_list,
                            })
        if NamedManager.named_pid():
            NamedManager.reload()


    # def reset_bind_conf_users(self, template_file: str, conf_file: str, user_list: list[str]) -> None:
    #     logger.info(f'Resetting bind config {conf_file}')
    #     template = self.jinja_env.get_template(template_file)
    #     data = { 
    #             'origin': self.origin, 
    #             'user_list': user_list,
    #             }
    #     print(data)
    #     data = template.render(data)
    #     Path(conf_file).write_text(data)

    def reset_all_user_zonefiles(self) -> None:
        '''Remove all user zone files and create new ones for user_list'''
        users_dir = USER_ZONES_DIR
        user_list = self.find_user_list()
        logger.info(f'Resetting user zones dir {users_dir}')
        try:
            shutil.rmtree(users_dir)
            os.mkdir(users_dir)
        except Exception as e:
            logger.error(f'Error resetting user zone dir {users_dir}: {e}')
        for user in user_list:
            self.reset_user_zonefile(user)

    def get_public_ip(self) -> str | None:
        urls = [
            "https://ifconfig.me",
            "https://api.ipify.org",
            "https://ipinfo.io/ip",
            "https://icanhazip.com",
        ]
        for url in urls:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    logger.info(f'Found public IP {response.text} from {url}')
                    ip = response.text.strip()
                    ipaddress.IPv4Address(ip) # Throws if ip is invalid
                    return ip
            except:
                logger.warning(f'Failed asking public IP to {url}')
                continue
        raise PublicIpNotFound()



    def write_template(self, template, dir, data):
        name, extension = os.path.splitext(template)
        if extension != '.j2':
            logger.error(f'Template file should have .j2 extension: {template}')
        template = self.jinja_env.get_template(template)
        data = template.render(data)
        file = Path(dir) / name
        Path(file).write_text(data)


    def reset_rndc(self):
        secret_raw = secrets.token_bytes(32)
        rndc_secret = base64.b64encode(secret_raw).decode()
        data = {'rndc_secret': rndc_secret}
        self.write_template(RNDC_CONF_TEMPLATE, BIND_DIR, data)
        self.write_template(NAMED_CONF_RNDC_TEMPLATE, BIND_DIR, data)

    def delete_all_named_config(self) -> None:
        self.backup()
        for item in Path(BIND_DIR).iterdir():
            try:
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()
            except Exception as e:
                logger.error(f'Failed deleting {item}: {e}')

    def backup(self) -> str | None:
        Path(BACKUPS_DIR).mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        tar_filename = f'bind-{timestamp}.tar.gz'
        backup_file = Path(BACKUPS_DIR) / tar_filename
        try:
            with tarfile.open(backup_file, 'w:gz') as tar:
                if Path(BIND_DIR).exists():
                    for item in Path(BIND_DIR).iterdir():
                        tar.add(item, arcname=item.name)
            logger.info(f'Backup created: {tar_filename}')
            return tar_filename
        except Exception as e:
            logger.error(f'Failed backup {backup_file}: {e}')
            return None

    def zone_data_updating_record_a(self, username: str, hostname: str, ip: str, ttl=None) -> str:
        # logger.info(f'Updating record for user {username}: {hostname} {ip} {ttl}')
        zonefile = Path(USER_ZONES_DIR) / username
        if not zonefile.exists():
            logger.error(f'Failed updating record: zone file does not exist for user {username}')
            raise RecordUpdateError('Zone file does not exist')
        zone_lines = zonefile.read_text().splitlines()
        pattern = re.compile(rf'^{re.escape(hostname)}\s+(\d+\s+)?IN\s+A\s+\d+\.\d+\.\d+\.\d+')
        soa_pattern = re.compile(
            r'^(\S*\s*(?:\d+\s+)?IN\s+SOA\s+\S+\s+\S+\s+\(?)\s*(\d+)(\s+\d+\s+\d+\s+\d+\s+\d+\)?.*)$',
            re.IGNORECASE,
        )
        record_found = False
        updated_zone_data = []
        ttl = f'{ttl}\t' if ttl else ''
        for line in zone_lines:
            soa_match = soa_pattern.match(line)
            if soa_match:
                now_sec = int(datetime.now().timestamp())
                old_serial = int(soa_match.group(2))
                new_serial = max(now_sec, old_serial + 1)
                updated_zone_data.append(f'{soa_match.group(1)}{new_serial}{soa_match.group(3)}')
            elif pattern.match(line):
                updated_zone_data.append(f'{hostname}\t{ttl}IN\tA\t{ip}')
                record_found = True
            else:
                updated_zone_data.append(line)
        if not record_found:
            updated_zone_data.append(f'{hostname}\t{ttl}IN\tA\t{ip}')
        updated_zone_data.append('') # Ending newline mandatory for zone records
        return '\n'.join(updated_zone_data)

    def update_a_record(self, username: str, hostname: str, ip: str, ttl=None) -> None:
        zone_data = self.zone_data_updating_record_a(username, hostname, ip, ttl)
        self.set_user_zonefile(username, zone_data)

    def generate_token(self) -> str:
        raw_token = secrets.token_hex(USER_TOKEN_LENGTH // 2)
        return '-'.join(raw_token[i:i+4] for i in range(0, len(raw_token), 4))

    # TODO: Are we loading user tokens too many times?
    def generate_unique_token(self) -> str:
        user_tokens = self.load_user_tokens()
        user_token = None
        while not user_token:
            token = self.generate_token()
            if token not in user_tokens.values():
                user_token = token
        return user_token

    def load_user_tokens(self) -> Dict[str, str]:
        tokens = {}
        for f_name in Path(USER_TOKENS_DIR).iterdir():
            try:
                if f_name.is_file():
                    username = f_name.stem
                    status = f_name.suffix.lstrip('.')
                    if status != 'inactive':
                        tokens[username]= f_name.read_text()
            except:
                continue
        return tokens

    def reset_user_token(self, username: str) -> str:
        token = self.generate_unique_token()
        token_file = Path(USER_TOKENS_DIR) / username
        token_file.write_text(token)
        return token

    # TODO: implement token expiration
    def get_user_token(self, username: str) -> str:
        user_tokens = self.load_user_tokens()
        if username in user_tokens:
            return user_tokens[username]
        else:
            return self.reset_user_token(username)

    def delete_user_token(self, username) -> None:
        token_file = Path(USER_TOKENS_DIR) / username
        token_file.unlink(missing_ok=True)

    def find_user_for_token(self, token: str) -> str|None:
        user_tokens = self.load_user_tokens()
        for user_name, user_token in user_tokens.items():
            if user_token == token:
                return user_name
        return None
