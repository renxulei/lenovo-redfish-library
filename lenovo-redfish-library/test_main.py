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

    ############# System ################
    #####################################
    
    msg = "python main.py -i %s -u %s -p %s get_all_bios_attributes --type current" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python main.py -i %s -u %s -p %s get_all_bios_attributes --type pending" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "python main.py -i %s -u %s -p %s get_bios_attribute --attribute_name BootModes_SystemBootMode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bios_attribute_metadata" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bios_attribute_available_value" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bios_attribute_available_value --attribute_name BootModes_SystemBootMode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bios_bootmode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_boot_order" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_cpu_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_memory_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_memory_inventory --id 1" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_ethernet_interfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_storage" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_simple_storage" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_storage_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_power_state" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_log --type system" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    #os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_system_reset_types" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_bios_attribute --attribute_name OperatingModes_ChooseOperatingMode --attribute_value MaximumPerformance" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    bootorder = '"ubuntu" "Hard Disk" "USB Storage" "CD/DVD Rom"'
    #bootorder = ['Hard Drive', 'CD/DVD Drive', 'ubuntu', 'Windows Boot Manager', 'UEFI: PXE IP4 Mellanox Network Adapter']
    msg = "python main.py -i %s -u %s -p %s set_system_boot_order --bootorder %s" % (ip, user, password, bootorder)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_bios_bootmode --bootmode UEFIMode" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_system_power_state --reset_type On" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")


    ############# Manager ################
    ##################### ################

    msg = "python main.py -i %s -u %s -p %s get_bmc_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python main.py -i %s -u %s -p %s get_bmc_networkprotocol" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "python main.py -i %s -u %s -p %s get_bmc_serialinterfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "python main.py -i %s -u %s -p %s get_bmc_ethernet_interfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bmc_hostinterfaces" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bmc_ntp" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_get_bmc_users" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_bmc_virtual_media" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_create_bmc_user --username abcd --password PASSW0RD12q --authority Supervisor " % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_delete_bmc_user --username abcd" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_bmc_networkprotocol --service IPMI --enabled 0" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_bmc_networkprotocol --service DHCPv6 --enabled 0" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_export_ffdc" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_export_ffdc --fsprotocol SFTP --fsip 10.245.100.159 --fsdir /home/sftp_root/upload --fsusername mysftp --fspassword wlylenovo" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_mount_virtual_media --image bios.iso --fsprotocol NFS --fsip 10.245.100.159 --fsdir /home/nfs " % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_umount_virtual_media --image bios.iso" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_mount_virtual_media --image efiboot.img --fsprotocol HTTP --fsip 10.103.62.175 --fsport 8080 --fsdir /upload " % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_umount_virtual_media --image efiboot.img" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_bmc_config_backup --backup_password Aa1234567" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s lenovo_bmc_config_restore --backup_password Aa1234567 --backup_file .\\bmc_config_backup.json" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s reset_bmc" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    # os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s set_bmc_ntp --ntp_server 2.2.2.2 3.3.3.3 --protocol_enabled 1" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    ############# Update ################
    #####################################

    msg = "python main.py -i %s -u %s -p %s get_firmware_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    # os.system(msg)
    print("")

    fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\Intel"
    image = "lnvgy_fw_uefi_ive160g-2.70_anyos_32-64.uxz"
    #image = "lnvgy_fw_xcc_cdi358g-4.80_anyos_noarch.uxz"
    msg = "python main.py -i %s -u %s -p %s lenovo_update_firmware --image %s --fsdir %s" % (ip, user, password, image, fsdir)
    #msg = "python main.py -i %s -u %s -p %s lenovo_update_firmware --image %s --fsprotocol SFTP --fsip 10.245.100.159 --fsdir /home/sftp_root/upload --fsusername mysftp --fspassword wlylenovo" % (ip, user, password, image)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    ############# Chassis ################
    #####################################

    msg = "python main.py -i %s -u %s -p %s get_pci_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_nic_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_fan_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_temperatures_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_psu_inventory" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_power_redundancy" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_power_voltages" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_power_metrics" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "python main.py -i %s -u %s -p %s get_power_limit" % (ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
