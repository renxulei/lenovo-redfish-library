###
#
# Lenovo Redfish examples - Lenovo Redfish Client
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
import warnings
import redfish
import configparser
import logging
import json
import traceback 
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#from requests.auth import HTTPBasicAuth
from redfish.rest.v1 import HttpClient
from utils import *

warnings.filterwarnings('ignore')

#LOGGER = logging.getLogger(__name__)

class LenovoRedfishClient(HttpClient):
    """A client for accessing lenovo Redfish service"""

    def __init__(self, ip='', username='', password='', \
                                configfile='config.ini', \
                                auth=''):
        """Initialize LenovoRedfishClient

        :param ip: The url of the remote system
        :type ip: str
        :param username: The user name used for authentication
        :type username: str
        :param password: The password used for authentication
        :type password: str
        :param configfile: config.ini file
        :type configfile: str
        :param auth: basic or session
        :type auth: str
        """

        self._ip = ip
        self._user = username
        self._password = password
        self._auth = auth
        self._systemid = ''
        self._managerid = ''
        self._chassisid = ''
        self._cafile = ''
        self._fsprotocol = ''
        self._fsport = ''
        self._fsip = ''
        self._fsusername = ''
        self._fspassword = ''
        self._fsdir = ''
        self._suburl_system = ''
        self._suburl_manager = ''
        self._suburl_chassis = ''
        self._long_connection = False
        self._bmc_type = ''

        try:
            config_ini_info = {}
            # Get configuration file info
            result = read_config(configfile)
            
            if result['ret'] == True:
                if self._ip == '' or self._ip == None:
                    self._ip = result['entries']['bmcip']
                if self._user == '' or self._user == None:
                    self._user = result['entries']['bmcusername']
                if self._password == '' or self._password == None:
                    self._password = result['entries']['bmcuserpassword']
                if (self._auth == '' or self._auth == None) and result['entries']['auth'] != '':
                    self._auth = result['entries']['auth']
 
                self._systemid = result['entries']['systemid']
                self._managerid = result['entries']['managerid']
                self._cafile = result['entries']['cafile']
                self._fsprotocol = result['entries']['fsprotocol']
                self._fsport = result['entries']['fsport']
                self._fsip = result['entries']['fsip']
                self._fsusername = result['entries']['fsusername']
                self._fspassword = result['entries']['fspassword']
                self._fsdir = result['entries']['fsdir']

            if self._auth not in ['session', 'basic']:
                self._auth = 'session'
          
            login_host = "https://" + self._ip
            super(LenovoRedfishClient, self).__init__(base_url=login_host, \
                        username=self._user, password=self._password, \
                        default_prefix='/redfish/v1', capath=None, \
                        cafile=None, timeout=None, max_retry=3)
        except Exception as e:
            LOGGER.error("Error_message: %s." % repr(e))
 
    # Once enabling this, logout will not clear the session info.
    # When you want to run several functions continuously, 
    # you can enable this, this will save the time to setup connection. 
    def _set_long_connection(self, is_enable=True):
        """enable/disable long connection"""
        self._long_connection = is_enable

    def _find_system_resource(self):
        if self._suburl_system != '':
            return self._suburl_system

        suburl = '/redfish/v1/Systems'
        result = self._get_url(suburl)

        if result['ret'] == True:
            for member in result['entries']['Members']:
                if self._systemid == '':
                    self._suburl_system = member['@odata.id']
                    return self._suburl_system
                if self._systemid == member['@odata.id'].split("/")[-1]:
                    self._suburl_system = member['@odata.id']
                    return self._suburl_system
            if self._suburl_system == '':
                LOGGER.error("Error_message: Failed to find the system resource. System id is %s ." % self._systemid)
        return self._suburl_system


    def _find_manager_resource(self):
        if self._suburl_manager != '':
            return self._suburl_manager

        suburl = '/redfish/v1/Managers'
        result = self._get_url(suburl)
        if result['ret'] == True:
            for member in result['entries']['Members']:
                if self._managerid == '':
                    self._suburl_manager = member['@odata.id']
                    return self._suburl_manager
                if self._managerid == member['@odata.id'].split("/")[-1]:
                    self._suburl_manager = member['@odata.id']
                    return self._suburl_manager
            if self._suburl_manager == '':
                LOGGER.error("Error_message: Failed to find the manager resource. Manager id is %s ." % self._managerid)
        return self._suburl_manager


    def _find_chassis_resource(self):
        if self._suburl_chassis != '':
            return self._suburl_chassis

        suburl = '/redfish/v1/Chassis'
        result = self._get_collection(suburl)
        if result['ret'] == True:
            for member in result['entries']:
                if self._chassisid == '':
                    # For some density server or highend server, we may have multiple chassis.
                    # We must find the chassis linked with one system.
                    if 'Links' in member and 'ComputerSystems' in member['Links']:
                        self._suburl_chassis = member['@odata.id']
                        return self._suburl_chassis
                if self._chassisid == member['@odata.id'].split("/")[-1]:
                    self._suburl_chassis = member['@odata.id']
                    return self._suburl_chassis
            if self._suburl_chassis == '':
                LOGGER.error("Error_message: Failed to find the chassis resource. Chassis id is %s ." % self._chassisid)
        return self._suburl_chassis

    def login(self, username=None, password=None, auth=None):
        changed = False
        if username != None and self._user != username:
            changed = True
            self._user = username
        if password != None and self._password != password:
            changed = True
            self._password = password
        if auth != None and self._auth != auth:
            changed = True
            self._auth = auth

        # re-create connection once user/password/auth specified
        if changed:
            self.set_session_key(None)
            self.set_authorization_key(None)
            return super(LenovoRedfishClient, self).login(username=self._user, password=self._password, auth=self._auth)

        if (self.get_session_key() != None and self._auth == 'session') or \
           (self.get_authorization_key() != None and self._auth == 'basic'):
            pass
        else:
            return super(LenovoRedfishClient, self).login(username=self._user, password=self._password, auth=self._auth)
    
    def logout(self):
        # if long_connection is enabled, keep current session.
        if self._long_connection == True:
            return

        if self.get_session_key() == None and self.get_authorization_key() == None:
            return

        # Logout of the current session. If logout failed, clear sessionkey or authorizationkey anyway.
        try:
            super(LenovoRedfishClient, self).logout()
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            LOGGER.error("Failed to log out. Error message: %s" % repr(e))
        finally:
            # Logout of the current session
            self.set_session_key(None)
            self.set_authorization_key(None)

    def _get_url(self, suburl):
        try:
            resp = self.get(suburl)
            if resp.status in [200]:
                return {'ret': True, 'entries': resp.dict}
            else:
                msg = "Failed to get %s. Error message: %s" % (suburl, str(resp))
                LOGGER.error(msg)
                return {'ret': False, 'msg': msg}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get %s. Error message: %s" % (suburl, repr(e))
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}


    def _get_collection(self, suburl):
        data = list()
        suburl_result = self._get_url(suburl)
        if suburl_result['ret'] == True:
            if 'Members' in suburl_result['entries']:
                for member in suburl_result['entries']['Members']:
                    memberurl_result = self._get_url(member['@odata.id'])
                    if memberurl_result['ret'] == True:
                        data.append(memberurl_result['entries'])
                    else:
                        return memberurl_result
                result = {'ret': True, 'entries': data}
                return result
        else:
            return suburl_result

    def _task_monitor(self, task_uri, wait_time=10):
        """Monitor task status
        :params task_uri: task uri for tracking the update status.
        :type task_uri: string
        :params wait_time: maximum time(minutes) to wait the task complete. 
        :type wait_time: int
        :returns: returns the task state and task information.
        """
        END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended", "Done", "Failed when Flashing Image."]
        time_start=time.time()
        while True:
            response_task_uri = self.get(task_uri, None)
            if response_task_uri.status in [200, 202]:
                if "TaskState" in response_task_uri.dict:
                    task_state = response_task_uri.dict["TaskState"]
                else:
                    result = {'ret': False, 'msg': "Failed to find task state.", 'entries': response_task_uri.dict}
                    return result
                # Monitor task status until the task terminates
                if task_state in END_TASK_STATE:
                    if task_state == "Completed":
                        result = {'ret': True, 'msg': "Task completed successfully.", 'entries': response_task_uri.dict}
                    else:
                        result = {'ret': False, 'msg': "Task completed abnormally.", 'entries': response_task_uri.dict}
                    return result
                else:
                    time_now = time.time()
                    # wait for max 10 minutes to avoid endless loop.
                    wait_seconds = wait_time * 60
                    if time_now - time_start > wait_seconds:
                        result = {'ret': False, 'msg':  "Task is not completed in %s minutes expected." % wait_time, 'entries': response_task_uri.dict}
                        return result
                    time.sleep(10)
            else:
                result = {'ret': False, 'msg': "Failed to get the info of task '%s'. Error code is %s. Error message is %s. " % \
                          (task_uri, response_task_uri.status, response_task_uri.text)}
                LOGGER.error(result['msg'])
                return result

# TBU
if __name__ == "__main__":
    # initiate LenovoRedfishClient object, specify ip/user/password/authentication.
    lenovo_redfish = LenovoRedfishClient('10.245.39.153', 'renxulei', 'PASSW0RD12q', auth='session')
    #lenovo_redfish = LenovoRedfishClient('10.245.39.251', 'renxulei', 'PASSW0RD12q', auth='session')

    # setup connection with bmc.
    lenovo_redfish.login()

    # performe management actions. get/set info.
    #result = lenovo_redfish.get_cpu_inventory()
    #result = lenovo_redfish.get_all_bios_attributes('pending')
    #result = lenovo_redfish.get_all_bios_attributes('current')
    #result = lenovo_redfish.get_bios_attribute('BootModes_SystemBootMode')
    #result = lenovo_redfish.get_bios_attribute_metadata()
    #result = lenovo_redfish.get_bios_bootmode()
    #result = lenovo_redfish.get_bmc_inventory()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_serialinterfaces()
    #result = lenovo_redfish.get_bmc_ethernet_interfaces()
    #result = lenovo_redfish.get_bmc_virtual_media()
    #result = lenovo_redfish.get_bmc_hostinterfaces()
    #result = lenovo_redfish.get_memory_inventory()
    #result = lenovo_redfish.get_system_ethernet_interfaces()
    #result = lenovo_redfish.get_system_inventory()
    #result = lenovo_redfish.get_system_storage()
    #result = lenovo_redfish.get_storage_inventory()
    #result = lenovo_redfish.get_pci_inventory()
    #result = lenovo_redfish.get_nic_inventory()
    #result = lenovo_redfish.get_fan_inventory()
    #result = lenovo_redfish.get_psu_inventory()
    #result = lenovo_redfish.get_power_redundancy()
    #result = lenovo_redfish.get_power_voltages()
    #result = lenovo_redfish.get_power_metrics()
    #result = lenovo_redfish.get_power_limit()
    #result = lenovo_redfish.get_temperatures_inventory()
    #result = lenovo_redfish.get_system_power_state()
    #result = lenovo_redfish.set_system_power_state('On')
    #result = lenovo_redfish.get_system_reset_types()
    #result = lenovo_redfish.get_bios_attribute_available_value('BootModes_SystemBootMode')
    #result = lenovo_redfish.get_bios_attribute_available_value('Q00001_Boot_Mode')
    #result = lenovo_redfish.get_bios_attribute_available_value('abcd')
    #result = lenovo_redfish.set_bios_attribute('OperatingModes_ChooseOperatingMode', 'MaximumPerformance')
    #result = lenovo_redfish.lenovo_get_bmc_users()
    #result = lenovo_redfish.lenovo_create_bmc_user('abcd','PASSW0RD=0',['Supervisor'])
    #result = lenovo_redfish.lenovo_delete_bmc_user('user90136')
    #result = lenovo_redfish.set_bmc_networkprotocol('DHCPv6', 0)
    #lenovo_redfish.login('USERID','PASSW0RD=2')
    #result = lenovo_redfish.get_bmc_networkprotocol()
    #result = lenovo_redfish.set_bios_bootmode('UEFIMode')
    #bootorder = ["ubuntu", "CD/DVD Rom", "Hard Disk", "USB Storage"]
    #bootorder = ['Hard Drive', 'CD/DVD Drive', 'ubuntu', 'Windows Boot Manager', 'UEFI: PXE IP4 Mellanox Network Adapter']
    #result = lenovo_redfish.set_bios_boot_order(bootorder)
    #result = lenovo_redfish.get_bios_boot_order()
    #result = lenovo_redfish.get_firmware_inventory()
    #result = lenovo_redfish.get_virtual_media()
    #result = lenovo_redfish.reset_bmc()
    ##result = lenovo_redfish.get_system_log()
    #ntp_server_list = ['2.2.2.2','3.3.3.3']
    #result = lenovo_redfish.set_bmc_ntp(ntp_server_list, 0)
    #result = lenovo_redfish.get_bmc_ntp()


    # XCC:
    #fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\Intel"
    #image = "lnvgy_fw_uefi_ive160g-2.70_anyos_32-64.uxz"
    #image = "lnvgy_fw_xcc_cdi358g-4.80_anyos_noarch.uxz"
    #result = lenovo_redfish.lenovo_update_firmware(image=image, fsdir=fsdir)
    #result = lenovo_redfish.lenovo_update_firmware(image=image, fsdir='/home/sftp_root/upload', fsprotocol='SFTP', fsip='10.245.100.159', fsusername='mysftp', fspassword='wlylenovo')    
    #result = lenovo_redfish.lenovo_export_ffdc()
    #result = lenovo_redfish.lenovo_export_ffdc(fsdir='/home/sftp_root/upload', fsprotocol='SFTP', fsip='10.245.100.159', fsusername='mysftp', fspassword='wlylenovo')
    #result = lenovo_redfish.lenovo_mount_virtual_media(image='bios.iso', fsdir='/home/nfs', fsprotocol='NFS', fsip='10.245.100.159')
    #result = lenovo_redfish.lenovo_mount_virtual_media(image='efiboot.img', fsdir='/upload', fsprotocol='HTTP', fsip='10.103.62.175', fsport='8080')
    #result = lenovo_redfish.lenovo_umount_virtual_media('bios.iso')
    #result = lenovo_redfish.lenovo_bmc_config_backup(backup_password='Aa1234567')
    #result = lenovo_redfish.lenovo_bmc_config_restore(backup_password='Aa1234567', backup_file='.\\aaaaaaaa.json')


    # AMD
    #image_uefi = "lnvgy_fw_uefi_cfe117k-5.10_anyos_32-64.rom"
    #image_bmc = "lnvgy_fw_bmc_ambt11n-2.53_anyos_arm.hpm"
    #fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\AMD"
    #result = lenovo_redfish.lenovo_update_firmware(image=image_uefi, target='UEFI', fsdir=fsdir)
    #result = lenovo_redfish.lenovo_update_firmware(image=image_bmc, target='BMC', fsdir=fsdir)
    #result = lenovo_redfish.lenovo_export_ffdc(fsdir='/upload', fsprotocol='HTTP', fsip='10.103.62.175')
    #result = lenovo_redfish.lenovo_mount_virtual_media(image='bios.iso', fsdir='/home/nfs', fsprotocol='NFS', fsip='10.245.100.159')
    #result = lenovo_redfish.lenovo_umount_virtual_media('bios.iso')
    #result = lenovo_redfish.lenovo_bmc_config_backup(backup_password='Aa1234567', httpip='10.103.62.175', httpport='8080', httpdir='upload/renxulei')
    #result = lenovo_redfish.lenovo_bmc_config_restore(backup_password='Aa1234567', backup_file='bmc-config.bin', httpip='10.103.62.175', httpport='8080', httpdir='upload/renxulei')






    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()
    #result = lenovo_redfish.get_bmc_ntp()


    # after completed management action, you must logout to clear session. 
    lenovo_redfish.logout()

    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))