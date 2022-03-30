netbox-vsphere.py syncs vSphere Objects to Netbox.
It reads Datacenters, Clusters, Hosts and VMs from vcenter (listed in config.ini alongside with user/pass) and pushes it in Netbox.
ESXi are identifying by serial numbers (server should be created in the Netbox first). CDP/LLDP info used for creating cables between server and switches.
VMs are scanning only in case of flag '1' in config.ini (vc1 = vc_fqdn.ru;login;password;<ins>1</ins>)
