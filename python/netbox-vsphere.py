import argparse
import configparser
import datetime
import fnmatch
import json
import logging
import os
import pynetbox
import urllib3
from ipaddress import ip_network
from json import dump, load
from pyVim.connect import Disconnect, SmartConnect, vim
from requests import Session

vmnicConvert = {
    'vmnic0': "vmnic0(c0p1)",
    'vmnic1': "vmnic1(c0p2)",
    'vmnic2': "vmnic2(c0p3)",
    'vmnic3': "vmnic3(c0p4)",
    'vmnic4': "vmnic4(c1p1)",
    'vmnic5': "vmnic5(c1p2)",
    'vmnic6': "vmnic6(c2p1)",
    'vmnic7': "vmnic7(c2p2)",
    'vmnic8': "vmnic8(c3p1)",
    'vmnic9': "vmnic9(c3p2)"
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
"""Remove VALUE_KEY for 7U2 and later"""
VALUE_KEY = 'value'

def script_parseArguments():
    parser = argparse.ArgumentParser(description='This script syncs vSphere to Netbox')
    parser.add_argument(
        '-c',
        '--config',
        type=str,
        default='config.ini',
        help='provide a path to a config file'
    )
    parser.add_argument(
        '-cl',
        '--cluster',
        type=str,
        help='provide an optional clustername'
    )
    parser.add_argument(
        '--host',
        type=str,
        help='provide a hostname'
    )
    parser.add_argument(
        '--veba',
        action="store_true",
        help='Sync only IP for VMs that being created by VEBA'
    )
    parser.add_argument(
        '--verbose',
        action="store_true",
        help='Change logging mode to info'
    )
    parser.add_argument(
        '--test',
        action="store_true",
        help='Activate test mode, also change netbox URL'
    )
    return parser.parse_args()


def script_checkConfig(config_path, log_path):
    return True


def script_initialization():
    global windowsPlatform, linuxPlatform, hostArg, clusterArg
    scan_type = "FULL"
    args = script_parseArguments()
    logdir = os.path.dirname(__file__) if args.test else '/var/log'
    if "/" in args.config:
        configPath = args.config
    else:
        configPath = os.path.join(os.path.dirname(__file__), args.config)
    if args.veba:
        logPath = os.path.join(logdir, 'veba_vSphere.log')
    else:
        logPath = os.path.join(logdir, 'vSphere.log')
    config = configparser.ConfigParser()
    config.read(configPath)
    if args.verbose or config['NETBOX']['logLevel'] == "INFO":
        logging.basicConfig(filename=logPath, level=logging.INFO)
    elif config['NETBOX']['logLevel'] == "WARNING":
        logging.basicConfig(filename=logPath, level=logging.WARNING)
    elif config['NETBOX']['logLevel'] == "ERROR":
        logging.basicConfig(filename=logPath, level=logging.ERROR)
    logging.warning("!\nScript is starting..." + str(datetime.datetime.now()))
    if "config.ini" not in configPath:
        logging.warning("Used config file " + "'" + args.config + "'")
    if args.test:
        netboxurl, dot_index = config['NETBOX']['netboxURL'], config['NETBOX']['netboxURL'].index('.')
        netboxurl = netboxurl[:dot_index] + '-test' + netboxurl[dot_index:]
    else:
        netboxurl = config['NETBOX']['netboxURL']
    logging.warning("!\nUsing " + netboxurl)
    nb = pynetbox.api(netboxurl, token=config['NETBOX']['netboxToken'])
    windowsPlatform = nb.dcim.platforms.get(name="Windows")
    if windowsPlatform is None:
        windowsPlatform = nb.dcim.platforms.create(
            name="Windows",
            slug="windows"
        )
    linuxPlatform = nb.dcim.platforms.get(name="Linux")
    if linuxPlatform is None:
        linuxPlatform = nb.dcim.platforms.create(
            name="Linux",
            slug="linux"
        )
    if args.host is not None:
        hostArg = args.host
        logging.warning("Syncing only host " + hostArg)
    else:
        hostArg = ""
    if args.cluster is not None:
        clusterArg = args.cluster
        logging.warning("Syncing only cluster " + clusterArg)
    else:
        clusterArg = ""
    if hostArg != "" or clusterArg != "":
        scan_type = "HOST"
    if args.veba:
        scan_type = "VEBA"
    wrongHosts = []
    return args, config, logging, nb, wrongHosts, True, scan_type


def script_get_vmware(host):
    result, cdp, host_network_system = {}, {}, host.configManager.networkSystem
    if (host_network_system is not None) and host_network_system.capabilities.supportsNetworkHints:
        for _ in host_network_system.QueryNetworkHint():
            vmnic_name = vmnicConvert[_.device]
            if _.connectedSwitchPort is not None:
                cdp[vmnic_name] = {}
                cdp[vmnic_name]['switchName'] = _.connectedSwitchPort.systemName \
                    if len(_.connectedSwitchPort.systemName) > 6 else _.connectedSwitchPort.devId
                cdp[vmnic_name]['switchPort'] = _.connectedSwitchPort.portId
            elif _.lldpInfo is not None:
                cdp[vmnic_name] = {}
                cdp[vmnic_name]['switchPort'] = _.lldpInfo.portId
                for lldpParam in _.lldpInfo.parameter:
                    if lldpParam.key == "System Name":
                        cdp[vmnic_name]['switchName'] = lldpParam.value.split(".")[0]
    result['pnic'] = {}
    for _ in host.config.network.pnic:
        vmnic_name = vmnicConvert[_.device]
        result['pnic'][vmnic_name] = {}
        if hasattr(_.linkSpeed, "speedMb"):
            description = str(_.linkSpeed.speedMb / 1000).rstrip('0').rstrip('.') + " Gbit/s Link Speed"
        else:
            description = "Not Connected"
        result['pnic'][vmnic_name]['macAddress'] = str.upper(_.mac)
        result['pnic'][vmnic_name]['speed'] = description
        if cdp.get(vmnic_name) is not None:
            result['pnic'][vmnic_name]['switchName'] = cdp[vmnic_name]['switchName']
            result['pnic'][vmnic_name]['switchPort'] = cdp[vmnic_name]['switchPort']
    result['vnic'] = {}
    for _ in host.config.network.vnic:
        result['vnic'][_.device] = {}
        result['vnic'][_.device]["macAddress"] = str.upper(_.spec.mac)
        result['vnic'][_.device]["mtu"] = _.spec.mtu
        result['vnic'][_.device]["description"] = _.portgroup if hasattr(_, "portgroup") else ""
        vmk_full_ip = _.spec.ip.ipAddress + "/" + _.spec.ip.subnetMask
        vmk_full_ip = "{}/{}".format(_.spec.ip.ipAddress, ip_network(vmk_full_ip, strict=False).prefixlen)
        result['vnic'][_.device]["ip"] = 'None' if fnmatch.fnmatch(vmk_full_ip, "169.254.*") else vmk_full_ip
    return result


def script_get_netbox(nb_host, nb):
    result, cables = {}, {}
    result['pnic'] = {}
    try:
        for _ in nb.dcim.cables.filter(device=nb_host.name):
            if _.termination_a.device.name == nb_host.name:
                cables[_.termination_a.name] = {}
                cables[_.termination_a.name]['switchName'] = _.termination_b.device.name
                cables[_.termination_a.name]['switchPort'] = _.termination_b.name
            else:
                cables[_.termination_b.name] = {}
                cables[_.termination_b.name]['switchName'] = _.termination_a.device.name
                cables[_.termination_b.name]['switchPort'] = _.termination_a.name
    except pynetbox.core.query.RequestError:
        logging.error("Error while getting cables from " + nb_host.name, exc_info=False)
    for _ in nb.dcim.interfaces.filter(device=nb_host.name, type__n="virtual", mgmt_only=False):
        result['pnic'][_.name] = {}
        result['pnic'][_.name]['macAddress'] = _.mac_address
        result['pnic'][_.name]['speed'] = _.description
        if cables.get(_.name) is not None:
            result['pnic'][_.name]['switchName'] = cables[_.name]['switchName']
            result['pnic'][_.name]['switchPort'] = cables[_.name]['switchPort']
    result['vnic'] = {}
    for _ in nb.dcim.interfaces.filter(device=nb_host.name, type="virtual"):
        result['vnic'][_.name] = {}
        result['vnic'][_.name]["macAddress"] = _.mac_address
        result['vnic'][_.name]["mtu"] = _.mtu
        result['vnic'][_.name]["description"] = _.description
        result['vnic'][_.name]["ip"] = \
            str(nb.ipam.ip_addresses.get(interface_id=nb.dcim.interfaces.get(name=_.name, device=nb_host.name).id))
    return result


def resync_netbox_host(vmware_host, nb_host, nb, logging, vmware_fqdn):
    cableList, oldCables = [], []
    nb_host_interface_list = nb.dcim.interfaces.filter(device=nb_host.name)
    for _ in nb_host_interface_list:
        if _.name == "ipmi":
            if not _.mgmt_only:
                _.mgmt_only = True
                _.save()
            if nb_host.primary_ip is not None:
                nb_host_primary_ip = nb.ipam.ip_addresses.get(nb_host.primary_ip.id)
                if nb_host_primary_ip.interface != _.id:
                    nb_host_primary_ip.interface = _.id
                    nb_host_primary_ip.save()
            elif nb.ipam.ip_addresses.get(
                    interface_id=nb.dcim.interfaces.get(name="ipmi", device=nb_host.name).id) is not None:
                nb_host.primary_ip = nb.ipam.ip_addresses.get(
                    interface_id=nb.dcim.interfaces.get(name="ipmi", device=nb_host.name).id).id
                nb_host.primary_ip4 = nb.ipam.ip_addresses.get(
                    interface_id=nb.dcim.interfaces.get(name="ipmi", device=nb_host.name).id).id
                nb_host.save()
        else:
            _.delete()
    for _ in vmware_host['pnic'].keys():
        nb_host_interface_type = 1000
        if "10 Gbit" in vmware_host['pnic'][_]['speed']:
            nb_host_interface_type = 1150
        elif "25 Gbit" in vmware_host['pnic'][_]['speed']:
            nb_host_interface_type = 1350
        nb_host_interface = nb.dcim.interfaces.create(
            device=nb_host.id,
            name=_,
            type=nb_host_interface_type,
            mac_address=vmware_host['pnic'][_]['macAddress'],
            description=vmware_host['pnic'][_]['speed']
        )
        if vmware_host['pnic'][_].get('switchName') is not None:
            nb_cable_label = "Wrong Label"
            try:
                port_number = vmware_host['pnic'][_]['switchPort'].split("/")[1] if "/" in vmware_host['pnic'][_]['switchPort']\
                    else ''.join(char for char in vmware_host['pnic'][_]['switchPort'] if char.isdigit())
                nb_cable_label = "(" + nb_host.rack.facility_id + ")" + nb_host.name + "-" \
                             + _.split("(")[1][:-1] + " (" \
                             + nb.dcim.devices.get(name=vmware_host['pnic'][_]['switchName']).rack.facility_id + ")" \
                             + vmware_host['pnic'][_]['switchName'] + "-p" + port_number
            except Exception:
                error_text = "Couldn't create Label for: " + nb_host.name
                logging.error(error_text)
            logging.info(vmware_host['pnic'][_]['switchName'] + " / " + vmware_host['pnic'][_]['switchPort'])
            nb_switch_interface = nb.dcim.interfaces.get(name=vmware_host['pnic'][_]['switchPort'],
                                                         device=vmware_host['pnic'][_]['switchName'])
            if nb_switch_interface is None:
                if "Eth1" in vmware_host['pnic'][_]['switchPort']:
                    nb_switch_interface = nb.dcim.interfaces.get(name="Eth-" + vmware_host['pnic'][_]['switchPort'].split("Eth")[1],
                                                                 device=vmware_host['pnic'][_]['switchName'])
                elif "ernet" in vmware_host['pnic'][_]['switchPort']:
                    nb_switch_interface = nb.dcim.interfaces.get(name=vmware_host['pnic'][_]['switchPort'].split("ernet")[0]
                                                                      + vmware_host['pnic'][_]['switchPort'].split("ernet")[1],
                                                    device=vmware_host['pnic'][_]['switchName'])
            if nb_switch_interface is not None:
                cableList.append(
                    dict(
                        termination_a_type='dcim.interface',
                        termination_a_id=nb_switch_interface.id,
                        termination_b_type='dcim.interface',
                        termination_b_id=nb_host_interface.id,
                        label=nb_cable_label
                    )
                )
            else:
                logging.warning(vmware_host['pnic'][_]['switchName'] + "-" + vmware_host['pnic'][_]['switchPort'] +
                                " isn't found in Netbox")
    try:
        nb.dcim.cables.create(cableList)
    except Exception:
        error_text = "Cables already exists while connecting: " + nb_host.name + " and " + \
                     vmware_host['pnic'][_]['switchPort']
        logging.error(error_text, exc_info=True)
    for _ in vmware_host['vnic'].keys():
        nb_host_vmk = nb.dcim.interfaces.create(
            device=nb_host.id,
            name=_,
            type='virtual',
            mtu=vmware_host['vnic'][_]['mtu'],
            mac_address=vmware_host['vnic'][_]['macAddress'],
            description=vmware_host['vnic'][_]['description']
        )
        logging.info(_ + " / " + vmware_host['vnic'][_]['ip'])
        if fnmatch.fnmatch(vmware_host['vnic'][_]['ip'],"10.*")or fnmatch.fnmatch(vmware_host['vnic'][_]['ip'],"172.*"):
            try:
                #cidr = ip_network(vmkFullip, strict=False).prefixlen
                #vmkFullip = "{}/{}".format(ip, cidr)
                nb_host_vmk_ip = nb.ipam.ip_addresses.get(address=vmware_host['vnic'][_]['ip'])
                if nb_host_vmk_ip is None:
                    nb.ipam.ip_addresses.create(
                        address=vmware_host['vnic'][_]['ip'],
                        status=1,
                        dns_name=vmware_fqdn,
                        interface=nb_host_vmk.id,
                        description=vmware_host['vnic'][_]['description']
                    )
                else:
                    nb_ip_update_dict = dict(
                        interface=nb_host_vmk.id,
                        description=vmware_host['vnic'][_]['description'],
                        dns_name=vmware_fqdn
                    )
                    nb_host_vmk_ip.update(nb_ip_update_dict)
            except Exception:
                logging.error("Incorrect VMKernel IP: " + vmware_host['vnic'][_]['ip'], exc_info=True)


def clear_netbox_old_tag(netbox, vm_name):
    netbox_vm = netbox.virtualization.virtual_machines.get(name=vm_name)
    old_tags = netbox_vm.tags
    old_tags.remove('old_vms')
    netbox_vm.tags = old_tags
    netbox_vm.save()


def fill_dict_from_netbox_vm(nb, netbox_vm):
    result = {'cluster': netbox_vm.cluster.name, 'status': netbox_vm.status.label,
              'os': netbox_vm.platform.name if netbox_vm.platform is not None else "",
              'vcpus': netbox_vm.vcpus, 'memory': netbox_vm.memory, 'disk': netbox_vm.disk,
              'comments': netbox_vm.comments}
    for vmInterface in nb.virtualization.interfaces.filter(virtual_machine=netbox_vm.name):
        result[vmInterface.name] = {}
        result[vmInterface.name]['mac_address'] = vmInterface.mac_address
        result[vmInterface.name]['description'] = vmInterface.description
        ips = nb.ipam.ip_addresses.filter(interface_id=vmInterface.id)
        ip_index = 1
        for ip in ips:
            result[vmInterface.name]["IP{}".format(ip_index)] = ip.address
            ip_index += 1
    if netbox_vm.primary_ip is not None:
        result['primary_ip'] = netbox_vm.primary_ip.address
    return result


def resync_netbox_vm(nb, vm_name, vsphere_vm, func_logging, scan_type):
    netbox_vm = None
    netbox_vm, first_ip = nb.virtualization.virtual_machines.get(name=vm_name), ""
    func_logging.info('vm name is ' + vm_name)
    func_logging.info(vsphere_vm['cluster'])
    if netbox_vm.cluster.name != vsphere_vm['cluster']:
        netbox_vm.cluster = nb.virtualization.clusters.get(name=vsphere_vm['cluster']).id
        func_logging.info('Change cluster name to ' + vsphere_vm['cluster'] + ' for ' + vm_name)
    if netbox_vm.status is not None and netbox_vm.status.label != vsphere_vm['status']:
        netbox_vm.status = 1 if vsphere_vm['status'] == 'Active' else 0
        func_logging.info('Change vm status to ' + vsphere_vm['status'] + ' for ' + vm_name)
    if netbox_vm.platform is not None and netbox_vm.platform.name != vsphere_vm['os']:
        netbox_vm.platform = windowsPlatform.id if "Windows" in vsphere_vm['os'] else linuxPlatform.id
        func_logging.warning('Change vm OS to ' + vsphere_vm['os'] + ' for ' + vm_name)
    if netbox_vm.vcpus != vsphere_vm['vcpus']:
        netbox_vm.vcpus = vsphere_vm['vcpus']
        func_logging.warning('Change vm vCPUs to ' + str(vsphere_vm['vcpus']) + ' for ' + vm_name)
    if netbox_vm.memory != vsphere_vm['memory']:
        netbox_vm.memory = vsphere_vm['memory']
        func_logging.warning('Change vm memory to ' + str(vsphere_vm['memory']) + ' for ' + vm_name)
    if netbox_vm.disk != vsphere_vm['disk']:
        netbox_vm.disk = vsphere_vm['disk']
        func_logging.warning('Change vm disk size to ' + str(vsphere_vm['disk']) + 'GB for ' + vm_name)
    if netbox_vm.comments != vsphere_vm['comments']:
        netbox_vm.comments = vsphere_vm['comments']
        func_logging.info('Change vm comments to ' + vsphere_vm['comments'] + ' for ' + vm_name)
    for _ in nb.virtualization.interfaces.filter(virtual_machine_id=netbox_vm.id):
        _.delete()
    for _ in vsphere_vm.keys():
        if 'vNIC' in _:
            nb_vm_intf = nb.virtualization.interfaces.create(
                virtual_machine=netbox_vm.id,
                status=1,
                name=_,
                type="virtual",
                mac_address=vsphere_vm[_]['mac_address'],
                description=vsphere_vm[_]['description']
            )
            for nbx_vm_ips in vsphere_vm[_].keys():
                if 'IP' in nbx_vm_ips:
                    if first_ip == "":
                        first_ip = vsphere_vm[_][nbx_vm_ips]
                    if scan_type == 'VEBA':
                        try:
                            old_tags = netbox_vm.tags
                            old_tags.remove('veba')
                            netbox_vm.tags = old_tags
                            func_logging.info('Removed tag "VEBA" for ' + vm_name)
                        except ValueError:
                            logging.error("Some problems with tag deletion", exc_info=True)
                    netbox_ip = None
                    netbox_ip = nb.ipam.ip_addresses.get(address=vsphere_vm[_][nbx_vm_ips])
                    if netbox_ip is None:
                        netbox_ip = nb.ipam.ip_addresses.create(
                            address=vsphere_vm[_][nbx_vm_ips],
                            status=1,
                            interface=nb_vm_intf.id,
                            description=vsphere_vm[_]['description'] + " " + vm_name
                        )
                    else:
                        if netbox_ip.interface is not None:
                            old_owner = None
                            if hasattr(netbox_ip.interface.virtual_machine, 'id'):
                                old_owner = nb.virtualization.virtual_machines.get(
                                    id=netbox_ip.interface["virtual_machine"]["id"])
                            elif hasattr(netbox_ip.interface.device, "id"):
                                old_owner = nb.dcim.devices.get(id=netbox_ip.interface["device"]["id"])
                            if old_owner is not None:
                                old_owner.primary_ip = None
                                old_owner.primary_ip4 = None
                                old_owner.save()
                        netbox_ip.interface = nb_vm_intf.id
                        netbox_ip.description = vsphere_vm[_]['description'] + " " + vm_name
                        netbox_ip.save()
    if first_ip != "":
        netbox_vm.primary_ip = nb.ipam.ip_addresses.get(address=first_ip).id
        netbox_vm.primary_ip4 = nb.ipam.ip_addresses.get(address=first_ip).id
    netbox_vm.save()


def sync_vms(vsphere_connection, netbox, func_logging, scan_type):
    vsphere_datacenter_list = [datacenter.name for datacenter in vsphere_connection.content.rootFolder.childEntity]
    netbox_vms, netbox_synced_vms, old_vms_names = {}, {}, {}

    if scan_type != 'VEBA':
        old_vms_names = {}
        try:
            old_vms_names = set([vm.name for vm in netbox.virtualization.virtual_machines.filter(tag=['old_vms'])])
        except pynetbox.core.query.RequestError:
            pass

    for _ in vsphere_datacenter_list:
        netbox_scope_vms = None
        if scan_type == 'VEBA':
            netbox_scope_vms = netbox.virtualization.virtual_machines.filter(cluster_group=_, tag=['veba'])
        else:
            netbox_scope_vms = netbox.virtualization.virtual_machines.filter(cluster_group=_)
        if netbox_scope_vms is not None:
            for vm in netbox_scope_vms:
                netbox_vms[vm.name] = fill_dict_from_netbox_vm(netbox, vm)

    for datacenter in vsphere_connection.content.rootFolder.childEntity:
        objList = vsphere_connection.content.viewManager.CreateContainerView(datacenter, [vim.VirtualMachine],
                                                                             recursive=True).view
        for vm in objList:
            if vm.config.template:
                func_logging.info('Skipping Template ' + vm.name)
            else:
                if scan_type == 'VEBA' and vm.name not in netbox_vms.keys():
                    continue
                if scan_type != 'VEBA':
                    netbox_synced_vms[vm.name] = True
                vsphere_vm = {'cluster': vm.runtime.host.parent.name,
                              'status': "Active" if vm.runtime.powerState == "poweredOn" else "Offline",
                              'os': 'Windows' if 'Windows' in vm.config.guestFullName else 'Linux',
                              'vcpus': vm.summary.config.numCpu, 'memory': vm.summary.config.memorySizeMB,
                              'disk': (vm.summary.storage.committed + vm.summary.storage.uncommitted) // (1024 ** 3),
                              'comments': vm.summary.config.annotation if vm.summary.config.annotation is not None else ""}

                debugVM = vm.name + " / " + vm.runtime.host.parent.name + " / " + vm.runtime.powerState + " / " + "vCPU " \
                          + str(vm.summary.config.numCpu) + " Memory " + str(vm.summary.config.memorySizeMB) +\
                          " Storage " + str((vm.summary.storage.committed + vm.summary.storage.uncommitted) // (1024 ** 3))
                func_logging.info(debugVM)
                index = -1
                for nic in vm.guest.net:
                    if nic.network is not None:
                        index += 1
                        vsphere_vm["vNIC{}".format(index)] = {}
                        vsphere_vm["vNIC{}".format(index)]['mac_address'] = str.upper(nic.macAddress)
                        vsphere_vm["vNIC{}".format(index)]['description'], ip_index = nic.network, 1
                        if nic.ipConfig is not None:
                            for ip in nic.ipConfig.ipAddress:
                                ip_addr = "{}/{}".format(ip.ipAddress, ip.prefixLength)
                                func_logging.info(nic.macAddress + " / " + ip_addr)
                                if fnmatch.fnmatch(ip_addr, "10.*") or fnmatch.fnmatch(ip_addr, "172.*"):
                                    vsphere_vm["vNIC{}".format(index)]["IP{}".format(ip_index)] = ip_addr
                                    ip_index += 1
                                    if 'primary_ip' not in vsphere_vm.keys():
                                        vsphere_vm['primary_ip'] = ip_addr

                if vm.name in old_vms_names and scan_type != 'VEBA':
                    clear_netbox_old_tag(netbox, vm.name)

                if vm.name in netbox_vms.keys() and netbox_vms[vm.name] != vsphere_vm:
                    func_logging.info('vSphere_dict ' + str(vsphere_vm))
                    func_logging.info('Netbox_dict ' + str(netbox_vms[vm.name]))
                    resync_netbox_vm(netbox, vm.name, vsphere_vm, func_logging, scan_type)
                elif vm.name not in netbox_vms.keys():
                    nb_vm = None
                    nb_vm = netbox.virtualization.virtual_machines.get(name=vm.name)
                    if nb_vm is None:
                        nb_vm = netbox.virtualization.virtual_machines.create(
                            name=vm.name,
                            cluster=netbox.virtualization.clusters.get(name=vsphere_vm["cluster"]).id,
                        )
                        resync_netbox_vm(netbox, vm.name, vsphere_vm, func_logging, scan_type)
                    elif fill_dict_from_netbox_vm(netbox, nb_vm) != vsphere_vm:
                        resync_netbox_vm(netbox, nb_vm.name, vsphere_vm, func_logging, scan_type)
                else:
                    func_logging.info(vm.name + ' is the same')
    for _ in netbox_vms.keys():
        if _ not in netbox_synced_vms.keys() and scan_type != 'VEBA':
            old_vm = netbox.virtualization.virtual_machines.get(name=_)
            new_tags = old_vm.tags
            if 'old_vms' not in new_tags:
                new_tags.append('old_vms')
                old_vm.tags = new_tags
                old_vm.save()
                func_logging.info('Added tag "OLD_VMS" for ' + _)


def sync_vms_tags(vcenter_string, nb, logging):
    host = 'https://' + vcenter_string.split(";")[0]
    login = vcenter_string.split(";")[1]
    password = vcenter_string.split(";")[2]
    vc_session = Session()
    vc_session.verify = False
    vc_session.auth = (login, password)
    """
    For 7U2
    res = vc_session.post(f'{host}/api/session')
    vc_session.headers.update({'vmware-api-session-id': res.json()})
    """
    res = vc_session.post(f'{host}/rest/com/vmware/cis/session')
    vc_session.headers.update({'vmware-api-session-id': res.json()[VALUE_KEY]})
    vm_tags = {}
    for _ in vc_session.get(f'{host}/api/vcenter/tagging/associations').json()['associations']:
        if _['object']['type'] == 'VirtualMachine':
            """
            For 7U2
            vm_name = vc_session.get(f'{host}/api/vcenter/vm/{_["object"]["id"]}').json()['name']
            """
            vm_name = vc_session.get(f'{host}/rest/vcenter/vm/{_["object"]["id"]}').json()[VALUE_KEY]['name']
            if vm_name not in vm_tags:
                vm_tags[vm_name] = []
            """
            For 7U2
            tag_name = vc_session.get(f'{host}/api/cis/tagging/tag/{_["tag"]}').json()['name']
            """
            tag_name = \
                vc_session.get(f'{host}/rest/com/vmware/cis/tagging/tag/id:{_["tag"]}').json()[VALUE_KEY]['name']
            vm_tags[vm_name].append(tag_name)
    logging.info(str(vm_tags))
    old_vms_tag = {'old_vms'}
    for vm in vm_tags.keys():
        netbox_vm = nb.virtualization.virtual_machines.get(name=vm)
        netbox_vm_tags, vsphere_tags = set(netbox_vm.tags), set(vm_tags[vm])
        if netbox_vm_tags != vsphere_tags:
            vsphere_tags = vsphere_tags | old_vms_tag if 'old_vms' in netbox_vm_tags else vsphere_tags
            netbox_vm.tags = list(netbox_vm_tags | vsphere_tags)
            netbox_vm.save()


def script_syncObjects(connection, datacenter, nb, objectType, siteId, wrongHosts, logging, vcenter_string):
    objList = connection.content.viewManager.CreateContainerView(datacenter, objectType,
                                                                 recursive=True).view
    if objectType == [vim.HostSystem]:
        clusterGroup = nb.virtualization.cluster_groups.get(name=datacenter.name)
        if clusterGroup is None:
            clusterGroup = nb.virtualization.cluster_groups.create(name=datacenter.name, slug=datacenter.name)
        logging.info("Clustergroup is - " + clusterGroup.name)
        for host in objList:
            if (hostArg != host.name and hostArg != "") or (clusterArg != host.parent.name and clusterArg != ""):
                continue
            nbCluster, staging = None, False
            if host.parent.parent.name != 'Staging':
                nbCluster = nb.virtualization.clusters.get(name=host.parent.name, siteid=siteId)
                if host.name != host.parent.name:
                    if nbCluster is None:
                        nbCluster = nb.virtualization.clusters.create(
                            name=host.parent.name,
                            slug=host.parent.name,
                            type=1,
                            group=clusterGroup.id
                        )
                    elif nbCluster.group != clusterGroup.id and host.name != host.parent.name:
                        nbCluster.group = clusterGroup.id
                        nbCluster.save()
                    logging.info(host.name + " / " + str(nbCluster.name))
            else:
                logging.info(host.name + " is in Staging")
                staging = True
            serialKey = host.hardware.systemInfo.serialNumber
            if serialKey is None:
                for _ in host.hardware.systemInfo.otherIdentifyingInfo:
                    if _.identifierType.key == "ServiceTag":
                        serialKey = _.identifierValue
                        break
            if 'VMware' in serialKey:
                serialKey = 'VMware-42 3f ff ec 9a 10 af d1-2b de 09 a4 3a 99 3'
            nbHost = None
            try:
                nbHost = nb.dcim.devices.get(serial=serialKey)
            except ValueError:
                logging.error("Duplicate host's serial key: " + serialKey, exc_info=False)
                wrongHosts.append("Duplicate host's serial key: " + serialKey)
                continue
            if nbHost is None:
                wrongHosts.append("Host " + host.name + " with serial key - " + serialKey + " is not found")
                logging.error("Host " + host.name + " with serial key - " + serialKey + " is not found")
                continue
            elif nbCluster is not None:
                if nbCluster.name != "bad_clu01":
                    nbHost.cluster = nbCluster.id
                    nbCluster.site = nbHost.site
                    try:
                        nbHost.save()
                        nbCluster.save()
                    except pynetbox.core.query.RequestError:
                        wrongHosts.append("Host " + host.name + " with serial key - " + serialKey + " found in " +
                                          nbCluster.site.name)
                        logging.error("Host " + host.name + " with serial key - " + serialKey + " found in " +
                                      nbCluster.site.name)
                        continue
            elif staging:
                nbHost.cluster = None
                nbHost.save()
            logging.info(serialKey + " / " + str(nbHost.name))
            if host.runtime.connectionState != "notResponding" and host.runtime.connectionState != "disconnected":
                vmware_host, netbox_host = script_get_vmware(host), script_get_netbox(nbHost, nb)
                if vmware_host != netbox_host:
                    logging.info("VMware")
                    logging.info(vmware_host)
                    logging.info("Netbox")
                    logging.info(netbox_host)
                    resync_netbox_host(vmware_host, nbHost, nb, logging, host.name)
                else:
                    logging.info("Server is the same. Sync is skipping.")
            else:
                logging.error(host.name + " is not Responding. Sync is skipping.")


def script_syncVcenter(nb, logging, vcenter_string, wrongHosts, scan_type):
    site = nb.dcim.sites.get(name=(vcenter_string.split(";")[0]).split("-")[0])
    siteId = site.id if site is not None else nb.dcim.sites.get(name='test').id
    logging.warning(vcenter_string.split(";")[0])
    logging.warning(str(datetime.datetime.now()))
    try:
        connection = SmartConnect(
            host=vcenter_string.split(";")[0],
            user=vcenter_string.split(";")[1],
            pwd=vcenter_string.split(";")[2],
            disableSslCertValidation=True
        )
    except Exception:
        logging.error("vCenter connection error", exc_info=True)
        return "FAILURE"
    if connection is not None:
        if scan_type == 'FULL' or scan_type == 'HOST':
            for _ in connection.content.rootFolder.childEntity:
                script_syncObjects(connection, _, nb, [vim.HostSystem], siteId, wrongHosts, logging, vcenter_string)
        if vcenter_string.split(";")[3] == "1" and (scan_type == 'FULL' or scan_type == 'VEBA'):
            sync_vms(connection, nb, logging, scan_type)
            sync_vms_tags(vcenter_string, nb, logging)
        try:
            Disconnect(connection)
        except Exception:
            logging.error("vCenter disconnection error", exc_info=True)
            return "FAILURE"
    return "SUCCESS"

    
def script_writeHostFile(wrongHosts):
    hostlistPath = os.path.join(os.path.dirname(__file__), 'hostList.txt')
    hostListFile = open(hostlistPath, "w")
    hostListFile.write(str(datetime.datetime.now()) + "\n")
    wrongHosts.sort()
    hostListFile.write("\n".join(wrongHosts))
    hostListFile.close()


def main():
    args, config, logging, nb, wrongHosts, result, scan_type = script_initialization()
    if not result:
        return
    result_json, curr_date = {}, datetime.datetime.now()
    curr_date_key = str(curr_date.day) + '-' + str(curr_date.month) + '-' + str(curr_date.year)
    result_json[curr_date_key] = {}
    for configItem in config['DEFAULT']:
        vcenterString = config['DEFAULT'][configItem]
        try:
            result_json[curr_date_key][vcenterString.split(";")[0].split(".")[0]] = \
                script_syncVcenter(nb, logging, vcenterString, wrongHosts, scan_type)
        except Exception:
            result_json[curr_date_key][vcenterString.split(";")[0].split(".")[0]] = "FAILURE"
            logging.error("vCenter's objects sync error", exc_info=True)
    if "config.ini" in args.config and scan_type != 'VEBA':
        logdir = os.path.dirname(__file__) if args.test else '/var/log'
        json_path = os.path.join(logdir, "vSphere.json")
        with open(json_path, "a") as file_result:
            dump(result_json, file_result)
            file_result.write("\n")
    if scan_type != 'VEBA':
        script_writeHostFile(wrongHosts)
    logging.warning('Script is exiting...')
    logging.warning(str(datetime.datetime.now()))


if __name__ == '__main__':
    main()
