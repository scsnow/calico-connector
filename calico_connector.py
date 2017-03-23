#!/bin/python

import sys
import argparse
import libvirt
import etcd
import socket
import uuid
import logging
import json
from lxml import etree
from subprocess import call


ROOT_DIR = '/calico/v1'
PROFILE_DIR = ROOT_DIR + '/policy/profile'
HOST_DIR = ROOT_DIR + '/host'
CONFIG_DIR = ROOT_DIR + '/config'
NIC_MAX_LEN = 14
TAP_PREFIX = 'tap'
LIBVIRT_CONN = 'vz:///system'


class CalicoException(Exception):
    pass


class IPInUse(CalicoException):
    pass


class ProfileNotExists(CalicoException):
    pass


class ExecError(CalicoException):
    pass


class AttachInterfaceError(CalicoException):
    pass


class MACNotFound(CalicoException):
    pass


class LibvirtClient(object):
    def __init__(self):
        self.conn = libvirt.open(LIBVIRT_CONN)

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.conn.close()


class LibvirtInterfaceModel(object):
    def __init__(self, br_prefix, endpoint_id):
        self.br_name = (br_prefix + endpoint_id)[:NIC_MAX_LEN]
        self.tap_name = (TAP_PREFIX + endpoint_id)[:NIC_MAX_LEN]
        self._nic = etree.Element('interface', type='bridge')
        etree.SubElement(self._nic, 'source', bridge=self.br_name)
        etree.SubElement(self._nic, 'target', dev=self.tap_name)

    def __str__(self):
        return etree.tostring(self._nic)


class CalicoConnector(object):
    def __init__(self, args):
        parser = argparse.ArgumentParser(
            description='Connects Virtuozzo CT/VM to existing Calico network.')
        parser.add_argument('--instance',
                            required=True,
                            help='Instance name.')
        parser.add_argument('--ip',
                            required=True,
                            help='IPv4 address to assign to '
                                 'Calico workload endpoint.')
        parser.add_argument('--profile',
                            required=True,
                            help='Calico network profile.')
        parser.add_argument('--etcd-host',
                            help='Etcd host. Default: 127.0.0.1',
                            default='127.0.0.1')
        parser.add_argument('--etcd-port',
                            help='Etcd port. Default: 2379',
                            type=int,
                            default=2379)
        parser.add_argument('--prefix',
                            help='Network interface prefix. Default: cali',
                            default='cali')
        parser.add_argument('--workload',
                            help='Calico workload. Default: vz',
                            default='vz')
        parser.add_argument('--orchestrator',
                            help='Calico orchestrator. Default: vz',
                            default='vz')
        parser.add_argument('--debug',
                            help='Enable debug.',
                            action='store_true')
        self.args = parser.parse_args(args)
        self.host = socket.gethostname()
        self.client = etcd.Client(host=self.args.etcd_host,
                                  port=self.args.etcd_port)
        self.endpoint_id = str(uuid.uuid1())
        self.interface = LibvirtInterfaceModel(self.args.prefix, self.endpoint_id)
        logging_level = logging.DEBUG if self.args.debug else logging.INFO
        logging.basicConfig(stream=sys.stdout,
                            level=logging_level,
                            format='%(levelname)s: %(message)s')

    def _key_for_profile(self):
        return PROFILE_DIR + '/' + self.args.profile

    def _dir_for_base_workload(self):
        return HOST_DIR + "/%s/workload" % self.host

    def _dir_for_orchestrator(self):
        return self._dir_for_base_workload() + '/' + self.args.orchestrator

    def _dir_for_workload(self):
        return self._dir_for_orchestrator() + '/' + self.args.workload

    def _dir_for_endpoint(self):
        return self._dir_for_workload() + '/endpoint'

    def _key_for_endpoint(self, endpoint):
        return self._dir_for_endpoint() + '/' + endpoint

    @staticmethod
    def _key_for_config(config):
        return CONFIG_DIR + '/' + config

    def _check_prefix(self):
        logging.info("Checking interface prefix %s configured" %
                     self.args.prefix)

        prefix_key = self._key_for_config('InterfacePrefix')
        prefix_value = None
        try:
            prefix_value = self.client.read(prefix_key).value
        except etcd.EtcdKeyNotFound:
            logging.debug('InterfacePrefix key is not set in etcd')
        prefixes = prefix_value.split(',') if prefix_value else []
        if self.args.prefix not in prefixes:
            logging.info("Adding interface prefix %s to config" %
                         self.args.prefix)
            prefixes.append(self.args.prefix)
            prefix_new = ','.join(prefixes)
            self.client.write(prefix_key, prefix_new)

    def _check_ip_not_in_use(self):
        logging.info("Checking IP %s is not already assigned" % self.args.ip)

        # we need to walk through all endpoints across
        # all orchestrators and workloads
        endpoints = self.client.read(self._dir_for_base_workload(),
                                     recursive=True)
        for endpoint in endpoints.children:
            if endpoint.value is None:
                continue

            data = json.loads(endpoint.value)
            if (self.args.ip + '/32') in data['ipv4_nets']:
                raise IPInUse("IP %s is already assigned to endpoint %s" %
                              (self.args.ip, endpoint.key))

    def _check_profile_exists(self):
        logging.info("Checking profile %s exists" % self.args.profile)

        try:
            self.client.read(self._key_for_profile())
        except etcd.EtcdKeyNotFound:
            raise ProfileNotExists("Profile %s not exists" % self.args.profile)

    @staticmethod
    def _exec(command):
        rc = call(command)
        if rc:
            raise ExecError("Command '%s' failed with rc=%d" %
                            (' '.join(command), rc))

    def _add_bridge(self):
        logging.info("Adding new linux bridge %s" % self.interface.br_name)

        self._exec(['brctl', 'addbr', self.interface.br_name])
        self._exec(['ip', 'link', 'set', 'dev', self.interface.br_name, 'up'])

    def _add_interface(self):
        """Returns MAC address of added interface"""
        logging.info("Adding new interface %s to domain %s" %
                     (self.interface.tap_name, self.args.instance))

        mac_addr = None
        with LibvirtClient() as client:
            try:
                domain = client.lookupByName(self.args.instance)
                flags = (libvirt.VIR_DOMAIN_AFFECT_LIVE |
                         libvirt.VIR_DOMAIN_AFFECT_CONFIG)
                domain.attachDeviceFlags(str(self.interface), flags)
            except libvirt.libvirtError as ex:
                raise AttachInterfaceError("libvirtError caught: %s (%d)" %
                                           (ex.get_error_message(),
                                            ex.get_error_code()))
            else:
                # now we need to parse for generated MAC
                dom = etree.fromstring(domain.XMLDesc())
                mac = dom.xpath("//interface/mac[../target[@dev='%s']]" %
                                self.interface.tap_name)
                if mac:
                    mac_addr = mac[0].attrib['address']
                else:
                    raise MACNotFound("Cannot resolve MAC address of %s" %
                                      self.interface.tap_name)

        return mac_addr

    def _add_endpoint(self, mac):
        logging.info("Adding workload endpoint %s" % self.endpoint_id)

        endpoint = self._key_for_endpoint(self.endpoint_id)
        data = {"state": "active",
                "name": self.interface.br_name,
                "mac": mac,
                "profile_ids": [self.args.profile],
                "ipv4_nets": [self.args.ip + '/32'],
                "ipv6_nets": []}
        json_data = json.dumps(data)
        self.client.write(endpoint, json_data)

    def _check_orchestrator(self):
        logging.info("Checking orchestrator %s exists" %
                     self.args.orchestrator)

        dir_key = self._dir_for_orchestrator()
        try:
            self.client.read(dir_key)
        except etcd.EtcdKeyNotFound:
            logging.info("Creating orchestrator %s" %
                         self.args.orchestrator)
            self.client.write(dir_key, None, dir=True)

    def _check_workload(self):
        logging.info("Checking workload %s exists" %
                     self.args.workload)

        dir_key = self._dir_for_workload()
        try:
            self.client.read(dir_key)
        except etcd.EtcdKeyNotFound:
            logging.info("Creating workload %s" %
                         self.args.workload)
            self.client.write(dir_key, None, dir=True)
            self.client.write(self._dir_for_endpoint(), None, dir=True)

    def __call__(self, *args, **kwargs):
        self._check_prefix()
        self._check_orchestrator()
        self._check_workload()
        self._check_ip_not_in_use()
        self._check_profile_exists()
        self._add_bridge()
        mac = self._add_interface()
        self._add_endpoint(mac)

if __name__ == '__main__':
    calico = CalicoConnector(sys.argv[1:])
    try:
        sys.exit(calico())
    except CalicoException as e:
        logging.error(e)
