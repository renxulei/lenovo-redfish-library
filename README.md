# lenovo-redfish-library

Redfish library and commandline scriots for using the Redfish API to manage Lenovo servers

Description
----------

This project includes a set of Python scripts that utilize the Redfish API to manage Lenovo ThinkSystem servers.  The scripts use the DMTF python-redfish-library <https://github.com/DMTF/python-redfish-library>

This project provides:
lenovo_redfish_client.py  - Commandline script, manage server via redfish by using lenovo_redfish_library.
lenovo_redfish_sample.py  - Sample script, show how to use lenovo_redfish_library directly.
lenovo_redfish_library    - Library folder
+ __init__.py             - Init module to export main, ManagerClient, SystemClient, ChassisClient, UpdateClient Class and AccountClient Class.
+ main.py                 - Main module for commandline script, add/parse the parameters inputed from command line. 
+ system_client.py        - SystemClient Class, for system management. The commands supported, please refer to below.
+ manager_client.py       - ManagerClient Class, for bmc management. The commands supported, please refer to below.
+ chassis_client.py       - ChassisClient Class, for chassis management. The commands supported, please refer to below.
+ update_client.py        - UpdateClient Class, for update management. The commands supported, please refer to below.
+ account_client.py       - AccountClient Class, for account management. The commands supported, please refer to below.
+ redfish_base.py         - RedfishBase Class, base class of other class, for simplifying redfish interaction.
+ utils.py                - Utility module, for logging, reading config file and so on.
+ config.ini              - Config file, define ip, user, password and auth. These values will be used to setup redfish connection if they are not specified on command line.

test_script.py              - Test script for all commands, for XCC (Intel products)
test_script_amd.py          - Test script for all commands, for TSM (AMD 1P products)


For more information on the Redfish API, visit <http://redfish.dmtf.org/>

Installing
----------

* To install the python-redfish-library, get the code from <https://github.com/DMTF/python-redfish-library> , then:
    
    `python setup.py install`

* To install configparser:

    `pip install configparser`

Requirements
----------

* python-redfish-library need to be installed

Usage
----------
Use lenovo_redfish_client.py to perform management actions on target servers.
For examples:

    cd path-to-lenovo_redfish_client.py
    python lenovo_redfish_client.py -i ip -u user -p password subcommand parameters
    e.g. 'python lenovo_redfish_client.py -i 10.10.10.10 -u USERID -p PASSW0RD get_all_bios_attributes --type current', this command will get all current bios settings. 

* All subcommands supported and parameters needed:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  System subcommands:
    get_all_bios_attributes                    Help:  Get all attributes of bios
                --type                         Help:  'current' or 'pending', default is 'current'
    get_bios_attribute                         Help:  Get attibute value of one bios's attribute
                --attribute_name               Help:  Attribute name of bios
    get_bios_attribute_metadata                Help:  Get the registry info of bios attributes
    get_bios_attribute_available_value         Help:  Get available value of bios attirbute
                --attribute_name               Help:  Attribute name of bios, default is 'all'
    get_bios_bootmode                          Help:  Get bios's boot mode
    get_system_boot_order                      Help:  Get system's boot order
    get_cpu_inventory                          Help:  Get system's avaliable cpu inventory
    get_memory_inventory                       Help:  Get system's avaliable memory inventory
                --id                           Help:  Memory id, default is none
    get_system_ethernet_interfaces             Help:  Get system's ethernet interfaces
    get_system_storage                         Help:  Get system's storage, which are attached with storage controller
    get_system_simple_storage                  Help:  Get system's simple storage, which are attached with system directly
    get_storage_inventory                      Help:  Get all storages' inventory
    get_system_power_state                     Help:  Get system's power state
    get_system_inventory                       Help:  Get system's inventory
    get_system_reset_types                     Help:  Get system's available reset actions.
    get_system_boot_once                       Help:  Get current system's boot once setting or allowable boot source list.
                --type                         Help:  'current': current boot once setting. 'allow': allowable boot source list. Default is 'current'.
    set_bios_attribute                         Help:  Set one attribute of bios
                --attribute_name               Help:  Attribute name of bios
                --attribute_value              Help:  New value of this attribute
    lenovo_set_system_boot_order               Help:  Set system's boot order
                --bootorder                    Help:  Bios boot order list, like: 'CD/DVD Rom' 'Hard Disk'
    set_bios_bootmode                          Help:  Set system's boot mode
                --bootmode                     Help:  System's boot mode. please use 'get_bios_bootmode' to list available boot mode.
    set_system_boot_once                       Help:  Set system's boot once
                --bootsource                   Help:  System's boot once type. Please use 'get_system_boot_once' to get available value.
                --bootmode                     Help:  System's boot mode, 'UEFI' or 'Legacy'.
                --uefi_target                  Help:  Uefi target, which should be the Id of one virtual media instance.
                --enabled                      Help:  System's boot enabled, default is 'Once'. Allowable values are 'Once', 'Disabled' or 'Continuous'.
    set_system_power_state                     Help:  Set system's power state
                --reset_type                   Help:  Reset action, like 'GraceRestart', 'ForceRestart'. please use 'get_system_reset_types' to get available reset types.

  Manager subcommands:
    get_bmc_inventory                          Help:  Get bmc's inventory
    get_bmc_networkprotocol                    Help:  Get network services info of bmc
    get_bmc_serialinterfaces                   Help:  Get serial interfaces of bmc
    get_bmc_ethernet_interfaces                Help:  Get nic info of bmc
    get_bmc_virtual_media                      Help:  Get virtual media info of bmc
    get_bmc_hostinterfaces                     Help:  Get host interfaces of bmc
    get_bmc_ntp                                Help:  Get NTP setting of bmc
    get_event_log                              Help:  Get event logs of manager, system or chassis
                --type                         Help:  Log of 'manager', 'system' or 'chassis', default is 'manager'
    set_bmc_networkprotocol                    Help:  Set network service of bmc, like: enable/disable service, or change the port
                --service                      Help:  Service name, like: 'IPMI', 'NTP'
                --enabled                      Help:  Enable/disable the service. 1: enable, 0: disable.
                --port                         Help:  Port of network service
    lenovo_export_ffdc                         Help:  Export FFDC data
                --data_type                    Help:  Data collection type: 'ProcessorDump', 'ServiceDataFile' or 'BootPOSTDump'. Default is 'ProcessorDump'. Only for XCC
                --fsprotocol                   Help:  Transfer protocol. For XCC: 'SFTP', 'TFTP' or None(local save). Fox TSM: 'HTTP' only
                --fsip                         Help:  File server's ip, like: SFTP or TFTP server ip
                --fsport                       Help:  File server's port, only for HTTP. Default is '8080'
                --fsusername                   Help:  User name to access SFTP file server
                --fspassword                   Help:  Password to access SFTP file server
                --fsdir                        Help:  full path of dir on file server(SFTP/TFTP) under which ffdc file will be saved. for HTTP file server, fsdir should be the path to HTTP service root.
    lenovo_mount_virtual_media                 Help:  Mount virtual media
                --image                        Help:  Image's file name
                --fsprotocol                   Help:  Transfer protocol. For XCC: 'HTTP' or 'NFS'. Fox TSM: 'NFS' only
                --fsip                         Help:  File server's ip, like: HTTP or NFS server ip
                --fsdir                        Help:  full path of dir on NFS server. for HTTP file server, fsdir should be the path to HTTP service root.
                --fsport                       Help:  File server's port
                --inserted                     Help:  1 or 0. 1: True, 0: False
                --write_protected              Help:  1 or 0. 1: True, 0: False
    lenovo_umount_virtual_media                Help:  Umount virtual media
                --image                        Help:  Image name, virtual media with this name will be ejected
    lenovo_bmc_config_backup                   Help:  Back up the configuration of bmc
                --backup_password              Help:  Backup password for encrypting configuration file
                --backup_file                  Help:  Backup file of configuration, only for XCC. Default is 'bmc_config_backup.json' under current working directory.
                --httpip                       Help:  HTTP file server's ip, only for TSM
                --httpport                     Help:  HTTP file server's port, only for TSM
                --httpdir                      Help:  Path on HTTP file server to save the backup file, only for TSM
    lenovo_bmc_config_restore                  Help:  Restore the configuration of bmc
                --backup_password              Help:  Password for decrypting configuration file
                --backup_file                  Help:  Backup file of configuration, only for XCC. Default is 'bmc_config_backup.json' under current working directory.
                --httpip                       Help:  HTTP file server's ip, only for TSM
                --httpport                     Help:  HTTP file server's port, only for TSM
                --httpdir                      Help:  Path on HTTP file server to save the backup file, only for TSM
    reset_bmc                                  Help:  Set one attribute of bios
                --reset_type                   Help:  for XCC: 'GracefulRestart' or 'ForceRestart'. for TSM: 'ForceRestart' only
    set_bmc_ntp                                Help:  Set system's boot order
                --ntp_server                   Help:  NTP server list, like: '1.1.1.1' '2.2.2.2'
                --protocol_enabled             Help:  Enable NTP or not. 1: Enable, 0: Disable

  Chassis subcommands:
    get_pci_inventory                          Help:  Get pci devices' inventory
    get_nic_inventory                          Help:  Get nic devices' inventory
    get_fan_inventory                          Help:  Get fan devices' inventory
    get_temperatures_inventory                 Help:  Get temperature info
    get_psu_inventory                          Help:  Get psu's inventory
    get_power_redundancy                       Help:  Get power redundancy info
    get_power_voltages                         Help:  Get power voltages' inventory
    get_power_metrics                          Help:  Get power consumption's info
    get_power_limit                            Help:  Get power limitation of whole system

  Update subcommands:
    get_firmware_inventory                     Help:  Get firmware's inventory
    lenovo_update_firmware                     Help:  Update firmware
                --image                        Help:  Image's file name
                --target                       Help:  For XCC: 'BMC-Backup' only. For TSM: 'BMC' or 'UEFI'
                --fsprotocol                   Help:  Transfer protocol. For XCC: 'HTTPPUSH', 'SFTP' or 'TFTP'. Fox TSM: 'HTTPPUSH' only
                --fsip                         Help:  File server's ip, like: SFTP or TFTP server ip
                --fsdir                        Help:  Full path of dir on file server(SFTP/TFTP) or local machine(HTTPPUSH), under which image is saved.
                --fsusername                   Help:  User name to access SFTP file server
                --fspassword                   Help:  Password to access SFTP file server

  Account subcommands:
    get_bmc_users                              Help:  Get user accounts of bmc
    lenovo_create_bmc_role                     Help:  Add new role of bmc
                --role                         Help:  new role id: self-defined role name.
                --privileges                   Help:  New role's privileges, like 'UserAccountManagement' 'RemoteConsoleAccess'
    lenovo_create_bmc_user                     Help:  Add new user account of bmc
                --username                     Help:  New user's name
                --password                     Help:  New user's password
                --role                         Help:  User's role: 'Administrator', 'Operator', 'ReadOnly' or other self-defined role name. If self-defined role name is specified, please ensure the role exists or specify the privileges.
                --privileges                   Help:  New user's privileges, like 'UserAccountManagement' 'RemoteConsoleAccess'
    update_bmc_user_password                   Help:  Update one bmc user's password. If you want to update the password for first-access, please use update_default_password command
                --username                     Help:  User name for password updating
                --password                     Help:  New password
    update_default_password                    Help:  Update one bmc user's password. If you want to update the password for first-access, please use update_default_password command
                --password                     Help:  New password
                --account_id                   Help:  Account id. Default is 1, id of user 'USERID'.
    delete_bmc_user                            Help:  Delete one user account of bmc
                --username                     Help:  User with this name will be deleted.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Contributing
----------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

Copyright and License
---------------------

Copyright 2020 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
