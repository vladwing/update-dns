#!/usr/bin/env python
from __future__ import print_function
import json
import argparse
from six.moves import urllib
import os.path
import os
import sys
import ssl
import logging
import subprocess

if sys.version_info > (3, 0):
    basestring = str


class NullLogger(object):
    def info(self, *args, **kwargs):
        pass

    warn = info
    error = info
    trace = info
    debug = info

    instance = None

    @classmethod
    def singleton(cls):
        if not cls.instance:
            cls.instance = cls()
        return cls.instance


class LoggerInjectable(object):
    @property
    def logger(self):
        if hasattr(self, "_logger"):
            return self._logger
        return NullLogger.instance()

    @classmethod
    def set_logger(cls, logger):
        cls._logger = logger


class Application(object):
    def __init__(self, name=None, description=None):
        self.name = name
        self.description = description
        self.init_all()
        if not self.check_requirements():
            self.quit(1)

    def init_all(self):
        self.init_args()
        self.init_logger(self.args.log_level)
        # initialize application specific behavior
        self.on_init()

    def on_init(self):
        raise NotImplementedError

    def init_logger(self, level=logging.INFO):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(self.app_name)
        self.logger.setLevel(level)

    @staticmethod
    def log_levels(log_level):
        log_level = log_level.upper()
        choices = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARN": logging.WARNING,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL,
                "CRIT": logging.CRITICAL,
        }
        try:
            return choices[log_level]
        except KeyError:
            msg = ', '.join([choice.lower() for choice in choices.keys()])
            msg = 'LogLevels: use one of {%s}'%msg
            raise argparse.ArgumentTypeError(msg)

    def init_args(self):
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument("--log-level", type=self.log_levels, default="INFO", help="Log level", dest="log_level")
        self.on_init_args(parser)
        self.args = parser.parse_args()

    def on_init_args(self, parser):
        raise NotImplementedError

    def error_message(self, message):
        print("%s: error: %s" % (sys.argv[0], message))

    def check_requirements(self):
        raise NotImplementedError

    def inject_logger(self, classList):
        for cls in classList:
            if not issubclass(cls, LoggerInjectable):
                raise TypeError("%s needs to be derived from LoggerInjectable" % cls.__name__)
            cls.set_logger(self.logger)

    @property
    def app_name(self):
        if self.name is None:
            return ".".join(os.path.basename(sys.argv[0]).split(".")[:-1])
        return self.name

    def start(self):
        self.main()

    def quit(self, error_code=0):
        sys.exit(error_code)

    def main(self):
        raise NotImplementedError


class LinodeRequest(LoggerInjectable, object):
    @classmethod
    def API_URL(cls):
        return "https://api.linode.com/"

    @classmethod
    def set_api_key(cls, api_key):
        cls.api_key = api_key

    @property
    def API_KEY(self):
        return self.api_key

    @API_KEY.setter
    def API_KEY(self, value):
        self.api_key = value

    def __init__(self, action, parameters=None):
        super(LinodeRequest, self).__init__()
        self.action = action
        if parameters is not None:
            self.parameters = dict(parameters)
        else:
            self.parameters = dict()

    @classmethod
    def set_timeout(cls, timeout):
        cls._timeout = timeout

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        self._timeout = value

    @property
    def url(self):
        query = dict(self.parameters)
        query["api_action"] = self.action
        query["api_key"] = self.API_KEY
        return self.API_URL() + "?" + urllib.parse.urlencode(query)

    def get_data(self, timeout=None):
        if timeout is None:
            timeout = self.timeout
        self.logger.info("Calling Linode API %s(parameters=%s)", self.action, self.parameters)
        self.logger.debug("Connecting to '%s'. Timeout = %s", self.url, timeout)
        try:
            response = urllib.request.urlopen(self.url, timeout=self.timeout)
        except ssl.SSLError as e:
            self.logger.error(e.message)
            return {}
        data = response.read()
        return json.loads(data)


class IpAddress(LoggerInjectable, object):
    def __init__(self, address):
        super(IpAddress, self).__init__()
        if "." in address:
            if not self.is_valid_ipv4(address):
                raise TypeError("This is not a valid IPv4 address - %s" % address)
            self.type = "IPv4"
        elif ":" in address:
            if not self.is_valid_ipv6(address):
                raise TypeError("This is not a valid IPv6 address - %s" % address)
            self.type = "IPv6"
        else:
            raise TypeError("Invalid address %s" % address)
        self.address = address

    @staticmethod
    def is_valid_ipv4(address):
        parts = address.split(".")
        if len(parts) != 4:
            return False
        if len([x for x in parts if 0 <= int(x) < 2**8]) != 4:
            return False
        return True

    @staticmethod
    def is_valid_ipv6(address):
        parts = address.split(":")
        if len([x for x in parts if x == ""]) > 1:
            if parts[0] == "" and parts[1] == "" and parts[2] == "1":
                pass
            else:
                return False
        parts = [x for x in parts if x != ""]
        if len([x for x in parts if 0 <= int(x, 16) < 2**16]) != len(parts):
            return False
        return True

    @property
    def dns_type(self):
        return "A" if self.type == "IPv4" else "AAAA"

    def __repr__(self):
        return "%s(%s)" % (self.type, self.address)

    def __str__(self):
        return self.address

    def __eq__(self, other):
        if other is None:
            return False
        if isinstance(other, basestring):
            try:
                other = IpAddress(other)
            except Exception as e:
                return False
        return self.type == other.type and self.address == other.address

    def __ne__(self, other):
        return not self.__eq__(other)


class BaseAPIObject(LoggerInjectable, object):
    def __init__(self, requestClass=None):
        if requestClass is None:
            raise TypeError("You need to specify a requestClass")
        self.requestClass = requestClass


class DomainResource(BaseAPIObject):
    def __init__(self, config=None, domain=None, requestClass=None):
        super(DomainResource, self).__init__(requestClass=requestClass)
        if domain is not None:
            self.domain = domain
        self._target = None
        self.parse(config)
        self.modified = False
        self.config = config

    def parse(self, config, config_type=None):
        # this is Linode?
        if config_type == "Linode" or (config.get("RESOURCEID", None) is not None and config.get("NAME", None) is not None):
            self.name = config.get("NAME", None)
            self.resource_id = config.get("RESOURCEID", None)
            self.priority = int(config.get("PRIORITY", 0))
            self.dns_type = config.get("TYPE", None)
            if self.dns_type in ["A", "AAAA"]:
                self.target = IpAddress(config.get("TARGET"))
            else:
                self.target = config.get("TARGET")
        else:
            raise TypeError("Couldn't figure out which type of config you passed")

    def __repr__(self):
        return "%s(name='%s', id='%s', dns_type='%s', priority='%s', target='%s')" % (
            self.__class__.__name__, self.name, self.resource_id, self.dns_type, self.priority, self.target)

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        if self._target != value:
            self.modified = True
            self._target = value

    @property
    def address(self):
        if self.dns_type in ["A", "AAAA"]:
            return self.target
        else:
            raise KeyError("This record doesn't have an address")

    @address.setter
    def address(self, value):
        if isinstance(value, str) and isinstance(self.target, str):
            self.target = value
        elif isinstance(self.target, IpAddress):
            if isinstance(value, basestring):
                value = IpAddress(value)
            if value.dns_type == self.target.dns_type:
                self.target = value
            else:
                raise ValueError("You cannot change the address type of a record")
        else:
            raise ValueError("Invalid value to set the address to")


    def update(self):
        if not self.modified:
            self.logger.info("Resource was not modified. No update needed!")
            return True
        self.logger.info("Resource was modified. Update needed!")
        request = self.requestClass("domain.resource.update", parameters=dict(
            DomainId=self.domain.domain_id,
            ResourceID=self.resource_id,
            Name=self.name,
            Target=self.address))
        data = request.get_data()
        if "ERRORARRAY" in data and len(data["ERRORARRAY"]) > 0:
            self.logger.error("The request returned an error - %s", data)
            return False
        return True

class Domain(BaseAPIObject):
    def __init__(self, name=None, config=None, requestClass=None):
        super(Domain, self).__init__(requestClass=requestClass)
        if name is not None:
            self.name = name
        elif config is not None:
            self.parse(config)
        else:
            raise TypeError("You need to specify either 'name' or 'config'")
        self.resources = None
        self.config = config

    def parse(self, config, config_type=None):
        # this is Linode?
        if config_type == "Linode" or (config.get("DOMAIN", None) is not None and config.get("DOMAINID", None) is not None):
            self.name = config.get("DOMAIN")
            self.domain_id = config.get("DOMAINID")
            self.soa_email = config.get("SOA_EMAIL")
            self.enabled = config.get("STATUS") == 1
            self.default_ttl = config.get("TTL_SEC")
        else:
            raise TypeError("Couldn't figure out which type of config you passed")

    @classmethod
    def all_domains(cls, requestClass):
        request = requestClass("domain.list")
        data = request.get_data()
        if data.get("DATA", None) is None:
            cls.logger.error("Response doesn't contain the expected structure - %s", data)
            raise AttributeError("Response doesn't contain the expected structure")
        if "ERRORARRAY" in data and len(data["ERRORARRAY"]) > 0:
            cls.logger.error("The request returned an error - %s", data)
            raise TypeError("The request returned an error")
        domains = [cls(config=domain, requestClass=requestClass) for domain in data["DATA"]]
        return domains

    def __repr__(self):
        return "%s(name='%s', id='%s', soa_email='%s', enabled='%s', default_ttl='%s')" % (
            self.__class__.__name__, self.name, self.domain_id, self.soa_email, self.enabled, self.default_ttl)

    def get_resources(self, refresh=False):
        if refresh or self.resources is None:
            request = self.requestClass("domain.resource.list", dict(DomainId=self.domain_id))
            data = request.get_data()
            if data.get("DATA", None) is None:
                self.logger.error("Response doesn't contain the expected structure - %s", data)
                raise AttributeError("Response doesn't contain the expected structure")
            if "ERRORARRAY" in data and len(data["ERRORARRAY"]) > 0:
                cls.logger.error("The request returned an error - %s", data)
                raise TypeError("The request returned an error")
            self.resources = [DomainResource(config=resource, requestClass=self.requestClass, domain=self) for resource in data["DATA"]]
        return self.resources


class NetworkInterface(LoggerInjectable, object):
    def __init__(self, name):
        super(NetworkInterface, self).__init__()
        self.name = name

    @classmethod
    def all_interfaces(cls):
        proc = subprocess.Popen(["netstat -i"], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        lines = out.split('\n')[2:]
        interfaces = []
        for line in lines:
            if line != '':
                interfaces.append(cls(line.split()[0]))
        return interfaces

    def __repr__(self):
        return "%s(name='%s')" % (self.__class__.__name__, self.name)

    def get_addresses(self):
        proc = subprocess.Popen(["ip addr show dev %s | grep inet" % self.name], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        lines = out.split('\n')
        addresses = []
        for line in lines:
            line = line.strip()
            if line != '':
                addresses.append(IpAddress(line.split()[1].split("/")[0]))
        return addresses


class UpdateDNSApp(Application):
    def on_init(self):
        self.domains = None
        self.requestClass = LinodeRequest
        self.requestClass.set_timeout(self.args.timeout)
        self.requestClass.set_api_key(self.api_key)
        self.inject_logger([LinodeRequest, DomainResource, Domain, LoggerInjectable, IpAddress])

    def check_requirements(self):
        if self.api_key is None:
            self.error_message("argument --linode-api-key or LINODE_API_KEY environment variable required")
            return False
        if self.address is None:
            self.error_message("argument --address or --iface required")
            return False
        return True

    @property
    def api_key(self):
        if self.args.linode_api_key is not None:
            return self.args.linode_api_key
        return os.environ.get("LINODE_API_KEY", None)

    @property
    def timeout(self):
        return self.args.timeout

    @property
    def address(self):
        if self.args.addr is not None:
            return self.args.addr
        elif self.args.iface is not None:
            return self.args.iface.address
        else:
            return None

    def on_init_args(self, parser):
        parser.add_argument("--name", type=str, required=True, help="Name to update")
        parser.add_argument("--addr", type=IpAddress, help="IPv4 or IPv6 for name")
        parser.add_argument("--request-timeout", type=float, default=0.5, help="Timeout for each request operation", dest="timeout")
        parser.add_argument("--iface", type=str, help="Interface to get IP from instead of giving it manually")
        parser.add_argument("--linode-api-key", type=str, help="Linode API key", dest="linode_api_key")

    def get_domains(self, refresh=False):
        if not refresh or self.domains is not None:
            self.domains = Domain.all_domains(self.requestClass)
        return self.domains

    def main(self):
        fqdn = self.args.name
        domain_name = ".".join(fqdn.split(".")[-2:])
        host_name = ".".join(fqdn.split(".")[:-2])
        domains = [x for x in self.get_domains() if x.name == domain_name]
        if len(domains) != 1:
            self.logger.error("Funny ... There are multiple domains matching your domain name %s", domains)
            return self.quit(1)
        domain = domains[0]
        resources = [x for x in domain.get_resources() if x.name == host_name and x.dns_type == self.address.dns_type]
        if len(resources) == 0:
            self.logger.error("There are no resources matching your host name %s", domain.get_resources())
            return self.quit(1)
        if len(resources) > 1:
            self.logger.error("Funny ... There are multiple resources matching your host name %s", resources)
            return self.quit(1)
        resource = resources[0]
        resource.address = self.address
        if not resource.update():
            self.logger.error("Resource update failed")
            self.quit(1)
        else:
            self.logger.info("Resource update successful")
            self.quit(0)

if __name__ == "__main__":
    # interfaces = NetworkInterface.all_interfaces()
    # print(interfaces[4].get_addresses())
    app = UpdateDNSApp(name="update-dns", description="Update the DNS names with LINODE")
    app.start()
