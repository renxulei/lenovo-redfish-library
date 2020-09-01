###
#
# Lenovo Redfish Test Script for lenovo_redfish_library
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
import sys
import time


if __name__ == "__main__":

    # Change this according to the server you will test.
    ip = "10.245.39.251"
    user = "renxulei"
    password = "PASSW0RD12q"
    
    # Please define this according to your python environment, please ensure the version is 3.x
    #py_name = "python3"
    py_name = "python"

    ############# System ################
    #####################################
    
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_all_bios_attributes --type current" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_all_bios_attributes --type pending" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bios_attribute --attribute_name BootModes_SystemBootMode" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bios_attribute_metadata" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bios_attribute_available_value" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bios_attribute_available_value --attribute_name BootModes_SystemBootMode" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bios_bootmode" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_boot_order" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_boot_once" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_boot_once --type allow" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_cpu_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_memory_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_memory_inventory --id 1" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_ethernet_interfaces" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_storage" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_simple_storage" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_storage_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_power_state" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_event_log --type manager" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_system_reset_types" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_bios_attribute --attribute_name OperatingModes_ChooseOperatingMode --attribute_value MaximumPerformance" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    bootorder = '"ubuntu" "Hard Disk" "USB Storage" "CD/DVD Rom"'
    #bootorder = ['Hard Drive', 'CD/DVD Drive', 'ubuntu', 'Windows Boot Manager', 'UEFI: PXE IP4 Mellanox Network Adapter']
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_set_system_boot_order --bootorder %s" % (py_name, ip, user, password, bootorder)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_bios_bootmode --bootmode UEFIMode" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_system_power_state --reset_type On" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")


    ############# Manager ################
    ##################### ################

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_networkprotocol" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_serialinterfaces" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")    

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_ethernet_interfaces" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_hostinterfaces" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_ntp" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_users" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_bmc_virtual_media" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_create_bmc_user --username abcd --password PASSW0RD12q --role Administrator" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_create_bmc_user --username efjh --password PASSW0RD12q --role role1 --privileges RemoteConsoleAccess UserAccountManagement" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s delete_bmc_user --username abcd" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s delete_bmc_user --username efjh" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_bmc_networkprotocol --service IPMI --enabled 0" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_bmc_networkprotocol --service DHCPv6 --enabled 0" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_export_ffdc" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_export_ffdc --fsprotocol SFTP --fsip 10.245.100.159 --fsdir /home/sftp_root/upload --fsusername mysftp --fspassword wlylenovo" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_mount_virtual_media --image bios.iso --fsprotocol NFS --fsip 10.245.100.159 --fsdir /home/nfs " % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_umount_virtual_media --image bios.iso" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_mount_virtual_media --image efiboot.img --fsprotocol HTTP --fsip 10.103.62.175 --fsport 8080 --fsdir /upload " % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
    time.sleep(10)

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_umount_virtual_media --image efiboot.img" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_bmc_config_backup --backup_password Aa1234567" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_bmc_config_restore --backup_password Aa1234567 --backup_file .\\bmc_config_backup.json" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s reset_bmc" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    # os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s set_bmc_ntp --ntp_server 2.2.2.2 3.3.3.3 --protocol_enabled 1" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    ############# Update ################
    #####################################

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_firmware_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\Intel"
    image = "lnvgy_fw_uefi_ive160g-2.70_anyos_32-64.uxz"
    #image = "lnvgy_fw_xcc_cdi358g-4.80_anyos_noarch.uxz"
    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_update_firmware --image %s --fsdir %s" % (py_name, ip, user, password, image, fsdir)
    #msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s lenovo_update_firmware --image %s --fsprotocol SFTP --fsip 10.245.100.159 --fsdir /home/sftp_root/upload --fsusername mysftp --fspassword wlylenovo" % (py_name, ip, user, password, image)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    ############# Chassis ################
    #####################################

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_pci_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_nic_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_fan_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_temperatures_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_psu_inventory" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_power_redundancy" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_power_voltages" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_power_metrics" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")

    msg = "%s lenovo_redfish_client.py -i %s -u %s -p %s get_power_limit" % (py_name, ip, user, password)
    print(msg)
    sys.stdout.flush()
    os.system(msg)
    print("")
