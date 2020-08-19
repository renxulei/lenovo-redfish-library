###
#
# Lenovo Redfish Test Script for lenovo-redfish-library
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###

import os
import logging
import json
import argparse
import sys



if __name__ == "__main__":

    #usage()

    ip = "10.245.39.251"
    user = "renxulei"
    password = "PASSW0RD12q"
    
    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_cpu_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_all_bios_attributes --type current" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_all_bios_attributes --type pending" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_bios_attribute_metadata" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_bios_attribute_available_value" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_bios_attribute_available_value --attribute_name BootModes_SystemBootMode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_bios_bootmode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_boot_order" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_cpu_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_memory_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_memory_inventory --id 1" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_ethernet_interfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_storage" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_simple_storage" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_storage_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_power_state" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_log --type system" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s get_system_reset_types" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s set_bios_attribute --attribute_name OperatingModes_ChooseOperatingMode --attribute_value MaximumPerformance" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    bootorder = '"ubuntu" "Hard Disk" "USB Storage"'
    #bootorder = ['Hard Drive', 'CD/DVD Drive', 'ubuntu', 'Windows Boot Manager', 'UEFI: PXE IP4 Mellanox Network Adapter']
    msg = "python lenovo_system_client.py -i %s -u %s -p %s set_system_boot_order --bootorder %s" % (ip, user, password, bootorder)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s set_bios_bootmode --bootmode UEFIMode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_system_client.py -i %s -u %s -p %s set_system_power_state --reset_type On" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")


    ############# Manager ################
    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_networkprotocol" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_serialinterfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_ethernet_interfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_hostinterfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_ntp" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_get_bmc_users" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s get_bmc_virtual_media" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_create_bmc_user --username 'abcd' --password 'PASSW0RD=0' --authority 'Supervisor' " % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_delete_bmc_user --username 'abcd'" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s set_bmc_networkprotocol --service 'IPMI' --enabled 0" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_export_ffdc" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_mount_virtual_media --image 'bios.iso' --fsprotocol 'NFS' --fsip '10.245.100.159' --fsdir '/home/nfs' " % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_umount_virtual_media --image 'bios.iso'" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_bmc_config_backup --backup_password 'Aa1234567'" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s lenovo_bmc_config_restore" --backup_password 'Aa1234567'" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s reset_bmc" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    # os.system(msg)
    print("")

    msg = "python lenovo_manager_client.py -i %s -u %s -p %s set_bmc_ntp --ntp_server '2.2.2.2' '3.3.3.3' --protocol_enabled 1" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
