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

class InvalidSubdomainError(Exception):
    pass

class SubdomainUnavailableError(Exception):
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

    USER_ZONE_SEP = ':'

    @staticmethod
    def user_zone_filename(username: str, subdomain: str) -> str:
        if username == subdomain:
            return username
        return f'{username}{ZoneManager.USER_ZONE_SEP}{subdomain}'

    @staticmethod
    def parse_zone_filename(filename: str) -> tuple[str, str]:
        if ZoneManager.USER_ZONE_SEP in filename:
            username, subdomain = filename.rsplit(ZoneManager.USER_ZONE_SEP, 1)
            return username, subdomain
        return filename, filename

    @staticmethod
    def _is_zone_file(path: Path) -> bool:
        return (
            path.is_file()
            and not path.name.startswith('.')
            and not path.name.endswith(('.tmp', '.orig'))
        )

    def find_user_zones(self) -> Dict[str, str]:
        user_zones: Dict[str, str] = {}
        zones_dir = Path(USER_ZONES_DIR)
        if not zones_dir.exists():
            return user_zones
        for f in sorted(zones_dir.iterdir(), key=lambda p: p.name):
            if not self._is_zone_file(f):
                continue
            username, subdomain = self.parse_zone_filename(f.name)
            user_zones[username] = subdomain
        return user_zones

    def get_user_zonefile_path(self, username: str) -> Path | None:
        user_zones = self.find_user_zones()
        if username not in user_zones:
            return None
        subdomain = user_zones[username]
        return Path(USER_ZONES_DIR) / self.user_zone_filename(username, subdomain)

    def validate_subdomain(self, subdomain: str) -> str:
        if not isinstance(subdomain, str):
            raise InvalidSubdomainError('Subdomain cannot be empty.')
        trimmed = subdomain.strip()
        if not trimmed:
            raise InvalidSubdomainError('Subdomain cannot be empty.')
        if re.search(r'\s', trimmed):
            raise InvalidSubdomainError('Subdomain cannot contain spaces or whitespace.')
        if '@' in trimmed:
            raise InvalidSubdomainError('Subdomain cannot contain "@".')
        if '.' in trimmed:
            raise InvalidSubdomainError('Subdomain must be a single label and cannot contain dots (".").')
        if '*' in trimmed:
            raise InvalidSubdomainError('Subdomain cannot contain wildcard ("*").')
        if '_' in trimmed:
            raise InvalidSubdomainError(
                'Subdomain cannot contain underscores ("_"). Only letters, digits, and hyphens ("-") are allowed.'
            )
        if trimmed.startswith('-') or trimmed.endswith('-'):
            raise InvalidSubdomainError('Subdomain cannot start or end with a hyphen ("-").')
        try:
            ascii_label = trimmed.encode('idna').decode('ascii').lower()
        except UnicodeError:
            raise InvalidSubdomainError(
                'Subdomain contains invalid internationalized (IDN/Punycode) characters.'
            )
        if not ascii_label:
            raise InvalidSubdomainError('Subdomain cannot be empty.')
        if len(ascii_label) > 63:
            raise InvalidSubdomainError(
                f'Subdomain cannot exceed 63 characters (currently {len(ascii_label)} characters).'
            )
        if ascii_label.startswith('-') or ascii_label.endswith('-'):
            raise InvalidSubdomainError('Subdomain cannot start or end with a hyphen ("-").')
        if not re.match(r'^[a-z0-9-]+$', ascii_label):
            raise InvalidSubdomainError(
                'Subdomain can only contain letters, digits, and hyphens ("-").'
            )
        return ascii_label

    def reserved_subdomains(self) -> set[str]:
        reserved = {'ns'}
        root_suffix = '.' + self.origin.lower()
        for raw_line in self.custom_records().splitlines():
            line = raw_line.split(';', 1)[0].rstrip()
            if not line or line[0].isspace():
                continue
            token = line.split()[0]
            if token.startswith(('$', '@', '(', ')')):
                continue
            token_lower = token.lower()
            if token_lower.endswith('.'):
                if token_lower.endswith(root_suffix):
                    rel = token_lower[: -len(root_suffix)]
                    if rel:
                        reserved.add(rel.split('.')[0])
            else:
                reserved.add(token_lower.split('.')[0])
        return reserved

    def is_subdomain_available(self, subdomain: str, exclude_user: str | None = None) -> bool:
        try:
            normalized = self.validate_subdomain(subdomain)
        except InvalidSubdomainError:
            return False
        if normalized in self.reserved_subdomains():
            return False
        for user, existing_sub in self.find_user_zones().items():
            if exclude_user is not None and user == exclude_user:
                continue
            if existing_sub.lower() == normalized:
                return False
        return True

    def sanitize_default_subdomain(self, username: str) -> str:
        local_part = str(username).split('@', 1)[0]
        try:
            return self.validate_subdomain(local_part)
        except InvalidSubdomainError:
            cleaned = re.sub(r'[^a-z0-9-]+', '-', local_part.lower()).strip('-')
            cleaned = cleaned[:63].rstrip('-')
            return cleaned or 'user'

    def allocate_default_subdomain(self, username: str) -> str:
        base = self.sanitize_default_subdomain(username)
        if self.is_subdomain_available(base, exclude_user=username):
            return base
        i = 1
        while True:
            suffix = f'-{i}'
            prefix = base[: 63 - len(suffix)].rstrip('-') or 'user'
            candidate = f'{prefix}{suffix}'
            if self.is_subdomain_available(candidate, exclude_user=username):
                return candidate
            i += 1

    def get_user_subdomain(self, username: str) -> str:
        user_zones = self.find_user_zones()
        if username in user_zones:
            return user_zones[username]
        return self.allocate_default_subdomain(username)

    def user_zone_origin(self, username):
        return self.get_user_subdomain(username) + '.' + self.origin

    def get_user_zonefile(self, username: str) -> str:
        zonefile = self.get_user_zonefile_path(username)
        if zonefile is None or not zonefile.exists():
            logger.info(f'Zone file does not exist for user: {username}')
            subdomain = self.get_user_subdomain(username)
            self.reset_user_zonefile(username, subdomain=subdomain, reload_bind=False)
            self.reset_main_zone()
            self.reset_named_conf_local()
            zonefile = self.get_user_zonefile_path(username)
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
        return list(self.find_user_zones().values())

    def count_zone_records(self, zonefile_path: Path, origin: str) -> int:
        try:
            zone = dns.zone.from_file(str(zonefile_path), origin=origin, relativize=False)
            return sum(
                len(rdataset)
                for node in zone.nodes.values()
                for rdataset in node.rdatasets
            )
        except Exception as e:
            logger.warning(f'Failed counting records in {zonefile_path}: {e}')
            return 0

    def list_users_summary(self) -> list[dict]:
        users = []
        for username, subdomain in sorted(
            self.find_user_zones().items(), key=lambda item: item[0].lower()
        ):
            zonefile = Path(USER_ZONES_DIR) / self.user_zone_filename(username, subdomain)
            origin = f'{subdomain}.{self.origin}'
            users.append({
                'username': username,
                'alias': subdomain,
                'origin': origin,
                'record_count': self.count_zone_records(zonefile, origin),
            })
        return users

    def read_existing_user_zonefile(self, username: str) -> str | None:
        zonefile = self.get_user_zonefile_path(username)
        if zonefile is None or not zonefile.exists():
            return None
        return zonefile.read_text()

    def delete_user(self, username: str) -> bool:
        zonefile = self.get_user_zonefile_path(username)
        if zonefile is None or not zonefile.exists():
            return False
        zonefile.unlink(missing_ok=True)
        zonefile.with_name(zonefile.name + '.orig').unlink(missing_ok=True)
        self.delete_user_token(username)
        self.reset_main_zone()
        self.reset_named_conf_local()
        return True

    def list_backups(self) -> list[str]:
        backups_dir = Path(BACKUPS_DIR)
        if not backups_dir.exists():
            return []
        return sorted(
            (p.name for p in backups_dir.iterdir() if p.is_file() and not p.name.startswith('.')),
            reverse=True,
        )

    def _next_zone_serial(self, zonefile_path: str | Path) -> int:
        path = Path(zonefile_path)
        now_sec = int(datetime.now().timestamp())
        if not path.exists():
            return 1
        try:
            soa_pattern = re.compile(
                r'^\S*\s*(?:\d+\s+)?IN\s+SOA\s+\S+\s+\S+\s+\(?\s*(\d+)',
                re.IGNORECASE | re.MULTILINE,
            )
            match = soa_pattern.search(path.read_text())
            if match:
                old_serial = int(match.group(1))
                return max(now_sec, old_serial + 1)
        except Exception:
            pass
        return now_sec

    @staticmethod
    def _ensure_newer_mtime(path: Path, prev_mtime_ns: int | None) -> None:
        if prev_mtime_ns is None or not path.exists():
            return
        try:
            st = path.stat()
            if st.st_mtime_ns <= prev_mtime_ns:
                new_ns = prev_mtime_ns + 1_000_000_000
                os.utime(path, ns=(st.st_atime_ns, new_ns))
        except Exception:
            pass

    def reset_main_zone(self):
        user_list = self.find_user_list()
        serial = self._next_zone_serial(MAIN_ZONE_FILE)
        self.reset_zonefile(
            self.origin, ZONEFILE_TEMPLATE, MAIN_ZONE_FILE, user_list, serial=serial
        )

    def set_user_zonefile(self, username: str, zone_data: str) -> None:
        subdomain = self.get_user_subdomain(username)
        origin = subdomain + '.' + self.origin
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
        try:
            self.replace_zone_if_reloads(tmp_zonefile, username, subdomain=subdomain)
        except NamedReloadError as e:
            raise BadZoneFile('Zone seems OK but there was an error reloading Bind.')

    def replace_zone_if_reloads(
        self, tmp_zonefile: Path, username: str, subdomain: str | None = None
    ) -> None:
        if subdomain is None:
            subdomain = self.get_user_subdomain(username)
        zonefile = Path(USER_ZONES_DIR) / self.user_zone_filename(username, subdomain)
        zonefile_backup = zonefile.with_name(zonefile.name + '.orig')
        prev_mtime_ns = zonefile.stat().st_mtime_ns if zonefile.exists() else None
        if zonefile.exists():
            shutil.copy2(zonefile, zonefile_backup)
        tmp_zonefile.replace(zonefile)
        self._ensure_newer_mtime(zonefile, prev_mtime_ns)
        try:
            NamedManager.reload()
            zonefile_backup.unlink(missing_ok=True)
        except NamedReloadError:
            contents = zonefile.read_text()
            logger.error(f'Passed named-checkzone but reload error for user {username}:\n{contents}')
            if zonefile_backup.exists():
                shutil.copy2(zonefile_backup, zonefile)
                self._ensure_newer_mtime(zonefile, prev_mtime_ns)
                zonefile_backup.unlink(missing_ok=True)
            else:
                zonefile.unlink(missing_ok=True)
            try:
                NamedManager.reload()
            except NamedReloadError:
                logger.error(f'VERY BAD SITUATION: failed reverting a reload error for user {username}. ******')
                raise
            raise

    def reset_user_zonefile(
        self,
        username: str,
        subdomain: str | None = None,
        reload_bind: bool = True,
    ) -> str:
        existed_before = self.get_user_zonefile_path(username) is not None
        if subdomain is None:
            subdomain = self.get_user_subdomain(username)
        origin = subdomain + '.' + self.origin
        zonefile = Path(USER_ZONES_DIR) / self.user_zone_filename(username, subdomain)
        zone = self.reset_zonefile(origin, USER_ZONE_TEMPLATE, zonefile)
        if reload_bind:
            if not existed_before:
                self.reset_main_zone()
                self.reset_named_conf_local()
            elif NamedManager.named_pid():
                NamedManager.reload()
        return zone

    def change_user_origin(self, username: str, new_subdomain: str) -> str:
        normalized = self.validate_subdomain(new_subdomain)
        user_zones = self.find_user_zones()
        old_subdomain = user_zones.get(username)
        if old_subdomain is not None and old_subdomain.lower() == normalized:
            raise SubdomainUnavailableError(
                f'"{normalized}.{self.origin}" is already your current zone origin.'
            )
        if normalized in self.reserved_subdomains():
            raise SubdomainUnavailableError(
                f'Subdomain "{normalized}" is reserved and cannot be used.'
            )
        if not self.is_subdomain_available(normalized, exclude_user=username):
            raise SubdomainUnavailableError(
                f'Subdomain "{normalized}.{self.origin}" is already taken.'
            )

        old_file = (
            Path(USER_ZONES_DIR) / self.user_zone_filename(username, old_subdomain)
            if old_subdomain is not None
            else None
        )
        old_contents = (
            old_file.read_text()
            if old_file is not None and old_file.exists()
            else None
        )
        new_file = Path(USER_ZONES_DIR) / self.user_zone_filename(username, normalized)
        new_origin = f'{normalized}.{self.origin}'

        try:
            if old_file is not None and old_file.exists() and old_file != new_file:
                old_file.unlink()
            zone = self.reset_zonefile(new_origin, USER_ZONE_TEMPLATE, new_file)
            NamedManager.named_checkzone(new_origin, new_file)
            self.reset_main_zone()
            NamedManager.named_checkzone(self.origin, MAIN_ZONE_FILE)
            self.reset_named_conf_local()
            NamedManager.named_checkconf()
            return zone
        except Exception as e:
            logger.error(f'Failed changing origin for {username} to {normalized}: {e}')
            if new_file.exists():
                new_file.unlink(missing_ok=True)
            if old_file is not None and old_contents is not None:
                old_file.write_text(old_contents)
            try:
                self.reset_main_zone()
                self.reset_named_conf_local()
            except Exception as rollback_err:
                logger.error(f'Failed rolling back origin change for {username}: {rollback_err}')
            raise

    def custom_records(self):
        try:
            return Path(CUSTOM_RRS_FILE).read_text()
        except:
            return ''

    def reset_zonefile(
        self,
        origin: str,
        zone_template: str,
        zonefile: str | Path,
        user_list: list[str] | None = None,
        serial: int = 1,
    ) -> str:
        if user_list is None:
            user_list = []
        logger.info(f'Resetting zone {zonefile}')
        if not self.public_ip:
            raise ZoneCreationError('No public IP')
        try:
            target_path = Path(zonefile)
            prev_mtime_ns = target_path.stat().st_mtime_ns if target_path.exists() else None
            template = self.jinja_env.get_template(zone_template)
            # TODO: get custom records only for main zone, not for all
            data = {
                    'origin': origin,
                    'ns_ip': self.public_ip,
                    'user_list': user_list,
                    'custom_records': self.custom_records(),
                    'serial': serial,
                    }
            zone = template.render(data)
            target_path.write_text(zone)
            self._ensure_newer_mtime(target_path, prev_mtime_ns)
            return zone
        except:
            raise ZoneCreationError()


    def reset_named_conf_local(self) -> None:
        '''Reads all user zones from `users_dir` and resets bind config for their zones.'''
        user_zones_map = self.find_user_zones()
        user_list = list(user_zones_map.values())
        user_zones = [
            {
                'username': u,
                'subdomain': s,
                'filename': self.user_zone_filename(u, s),
            }
            for u, s in user_zones_map.items()
        ]
        self.write_template(NAMED_CONF_LOCAL_TEMPLATE, 
                            BIND_DIR, 
                            { 
                                'origin': self.origin, 
                                'user_list': user_list,
                                'user_zones': user_zones,
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
        '''Remove all user zone files and create new ones preserving each user's subdomain'''
        users_dir = USER_ZONES_DIR
        user_zones = self.find_user_zones()
        logger.info(f'Resetting user zones dir {users_dir}')
        try:
            shutil.rmtree(users_dir)
            os.mkdir(users_dir)
        except Exception as e:
            logger.error(f'Error resetting user zone dir {users_dir}: {e}')
        for user, subdomain in user_zones.items():
            self.reset_user_zonefile(user, subdomain=subdomain, reload_bind=False)
        if NamedManager.named_pid():
            NamedManager.reload()

    def get_public_ip(self) -> str | None:
        urls = [
            "https://ifconfig.me",
            "https://api.ipify.org",
            "https://ipinfo.io/ip",
            "https://icanhazip.com",
        ]
        for url in urls:
            try:
                response = requests.get(url, timeout=5)
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
        zonefile = self.get_user_zonefile_path(username)
        if not zonefile or not zonefile.exists():
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
                    if f_name.name.endswith('.inactive'):
                        continue
                    tokens[f_name.name] = f_name.read_text()
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
