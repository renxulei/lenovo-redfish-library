###
#
# Lenovo Redfish examples - Add event subscriptions
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

        self.__ip = ip
        self.__user = username
        self.__password = password
        self.__auth = auth
        self.__systemid = ''
        self.__managerid = ''
        self.__chassisid = ''
        self.__cafile = ''
        self.__fsprotocol = ''
        self.__fsport = ''
        self.__fsip = ''
        self.__fsusername = ''
        self.__fspassword = ''
        self.__fsdir = ''
        self.__suburl_system = ''
        self.__suburl_manager = ''
        self.__suburl_chassis = ''
        self.__long_connection = False
        self.__bmc_type = ''

        try:
            config_ini_info = {}
            # Get configuration file info
            result = read_config(configfile)
            
            if result['ret'] == True:
                if self.__ip == '':
                    self.__ip = result['entries']['bmcip']
                if self.__user == '':
                    self.__user = result['entries']['bmcusername']
                if self.__password == '':
                    self.__password = result['entries']['bmcuserpassword']
                if self.__auth == '' and result['entries']['auth'] != '':
                    self.__auth = result['entries']['auth']
 
                self.__systemid = result['entries']['systemid']
                self.__managerid = result['entries']['managerid']
                self.__cafile = result['entries']['cafile']
                self.__fsprotocol = result['entries']['fsprotocol']
                self.__fsport = result['entries']['fsport']
                self.__fsip = result['entries']['fsip']
                self.__fsusername = result['entries']['fsusername']
                self.__fspassword = result['entries']['fspassword']
                self.__fsdir = result['entries']['fsdir']

            if self.__auth == '' or self.__auth not in ['session', 'basic']:
                self.__auth = 'session'
          
            login_host = "https://" + self.__ip
            super(LenovoRedfishClient, self).__init__(base_url=login_host, \
                        username=self.__user, password=self.__password, \
                        default_prefix='/redfish/v1', capath=None, \
                        cafile=None, timeout=None, max_retry=3)
        except Exception as e:
            LOGGER.error("Error_message: %s." % repr(e))
 
    # Once enabling this, logout will not clear the session info.
    # When you want to run several functions continuously, 
    # you can enable this, this will save the time to setup connection. 
    def __set_long_connection(self, is_enable=True):
        """enable/disable long connection"""
        self.__long_connection = is_enable

    def __find_system_resource(self):
        if self.__suburl_system != '':
            return self.__suburl_system

        suburl = '/redfish/v1/Systems'
        result = self.__get_url(suburl)

        if result['ret'] == True:
            for member in result['entries']['Members']:
                if self.__systemid == '':
                    self.__suburl_system = member['@odata.id']
                    return self.__suburl_system
                if self.__systemid == member['@odata.id'].split("/")[-1]:
                    self.__suburl_system = member['@odata.id']
                    return self.__suburl_system
            if self.__suburl_system == '':
                LOGGER.error("Error_message: Failed to find the system resource. System id is %s ." % self.__systemid)
        return self.__suburl_system


    def __find_manager_resource(self):
        if self.__suburl_manager != '':
            return self.__suburl_manager

        suburl = '/redfish/v1/Managers'
        result = self.__get_url(suburl)
        if result['ret'] == True:
            for member in result['entries']['Members']:
                if self.__managerid == '':
                    self.__suburl_manager = member['@odata.id']
                    return self.__suburl_manager
                if self.__managerid == member['@odata.id'].split("/")[-1]:
                    self.__suburl_manager = member['@odata.id']
                    return self.__suburl_manager
            if self.__suburl_manager == '':
                LOGGER.error("Error_message: Failed to find the manager resource. Manager id is %s ." % self.__managerid)
        return self.__suburl_manager


    def __find_chassis_resource(self):
        if self.__suburl_chassis != '':
            return self.__suburl_chassis

        suburl = '/redfish/v1/Chassis'
        result = self.__get_collection(suburl)
        if result['ret'] == True:
            for member in result['entries']:
                if self.__chassisid == '':
                    # For some density server or highend server, we may have multiple chassis.
                    # We must find the chassis linked with one system.
                    if 'Links' in member and 'ComputerSystems' in member['Links']:
                        self.__suburl_chassis = member['@odata.id']
                        return self.__suburl_chassis
                if self.__chassisid == member['@odata.id'].split("/")[-1]:
                    self.__suburl_chassis = member['@odata.id']
                    return self.__suburl_chassis
            if self.__suburl_chassis == '':
                LOGGER.error("Error_message: Failed to find the chassis resource. Chassis id is %s ." % self.__chassisid)
        return self.__suburl_chassis

    def login(self, username=None, password=None, auth=None):
        # TBU. need to consider how to check if session exist or still alive, session maybe time out. 
        changed = False
        if username != None and self.__user != username:
            changed = True
            self.__user = username
        if password != None and self.__password != password:
            changed = True
            self.__password = password
        if auth != None and self.__auth != auth:
            changed = True
            self.__auth = auth

        # re-create connection once user/password/auth specified
        if changed:
            self.set_session_key(None)
            self.set_authorization_key(None)
            return super(LenovoRedfishClient, self).login(username=self.__user, password=self.__password, auth=self.__auth)

        if (self.get_session_key() != None and self.__auth == 'session') or \
           (self.get_authorization_key() != None and self.__auth == 'basic'):
            pass
        else:
            return super(LenovoRedfishClient, self).login(username=self.__user, password=self.__password, auth=self.__auth)
    
    def logout(self):
        # if long_connection is enabled, keep current session.
        if self.__long_connection == True:
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

    def __get_url(self, suburl):
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


    def __get_collection(self, suburl):
        data = list()
        suburl_result = self.__get_url(suburl)
        if suburl_result['ret'] == True:
            if 'Members' in suburl_result['entries']:
                for member in suburl_result['entries']['Members']:
                    memberurl_result = self.__get_url(member['@odata.id'])
                    if memberurl_result['ret'] == True:
                        data.append(memberurl_result['entries'])
                    else:
                        return memberurl_result
                result = {'ret': True, 'entries': data}
                return result
        else:
            return suburl_result

    def get_all_bios_attributes(self, bios_get='current'):
        """Get all bios attribute
        :params bios_get: 'current' setting or 'pending' setting(default is 'current')
        :type bios_get: string
        :returns: returns dict of all bios attributes when succeeded or error message when failed
        """

        if bios_get not in ['current', 'pending']:
            return {'ret': False, 'msg': "Please specify parameter with 'current' or 'pending'."}

        result = {}
        try:
            system_url = self.__find_system_resource()
            result_bios = self.__get_url(system_url + '/Bios')
            if result_bios['ret'] == False:
                return result_bios

            if bios_get == "current":
                # Get the bios url resource
                return {'ret': True, 'entries': result_bios['entries']['Attributes']}
            else:
                # Get pending url
                pending_url = result_bios['entries']['@Redfish.Settings']['SettingsObject']['@odata.id']
                result_pending_url = self.__get_url(pending_url)
                if result_pending_url['ret'] == False:
                    return result_pending_url

                # Get the pending url resource
                pending_attribute = result_pending_url['entries']['Attributes']
                current_attribute = result_bios['entries']['Attributes']
                changed_attribute = {}
                for key in pending_attribute:
                    if pending_attribute[key] != current_attribute[key]:
                        changed_attribute[key] = pending_attribute[key]
                return {'ret': True, 'entries': changed_attribute}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bios attributes. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bios_attribute(self, attribute_name):
        """get bios attribute by user specified    
        :params attribute_name: Bios attribute name by user specified
        :type attribute_name: string
        :returns: returns get bios attribute value when succeeded or error message when failed
        """
        result = {}
        try:
            result_bios = self.get_all_bios_attributes()
            if result_bios['ret'] == False:
                return result_bios

            bios_attribute = {}
            if attribute_name in result_bios['entries'].keys():
                bios_attribute[attribute_name] = result_bios['entries'][attribute_name]
                return {'ret': True, 'entries': bios_attribute}
            else:
                return {'ret': False, 'msg': " No this attribute %s in the bios attribute" % attribute_name}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bios attribute %s. Error message: %s." % (attribute_name, repr(e))
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bios_attribute_metadata(self):
        """Get bios attribute metadata
        :returns: returns String of message with bios registry json file name when succeeded or error message when failed
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            result = self.__get_url(system_url + '/Bios')

            if result['ret'] == False:
                return result
    
            # Get used AttributeRegistry from Bios url
            attribute_registry = result['entries']['AttributeRegistry']

            # Find the AttributeRegistry json file uri from Registries
            registry_url = "/redfish/v1/Registries"
            result = self.__get_url(registry_url)
            if result['ret'] != True:
                return result
            bios_registry_url = None
            members_list = result['entries']['Members']
            for registry in members_list:
                if attribute_registry in registry['@odata.id']:
                    bios_registry_url = registry['@odata.id']
            if bios_registry_url is None:
                return {'ret': False, 'msg': "Can not find %s in Registries" % (attribute_registry)}

            result = self.__get_url(bios_registry_url)
            if result['ret'] != True:
                return result
            bios_registry_json_url = result['entries']['Location'][0]['Uri']

            # Download the AttributeRegistry json file
            result = self.__get_url(bios_registry_json_url)
            return result
            #if result['ret'] != True:
            #    return result
            #filename = os.getcwd() + os.sep + bios_registry_json_url.split("/")[-1]
            #with open(filename, 'w') as f:
            #    json.dump(result['entries'], f, indent=2)
            #return {'ret': True, 'msg': "Download Bios AttributeRegistry file %s" % (bios_registry_json_url.split("/")[-1])}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bios attribute metadata. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bios_attribute_available_value(self, attribute_name='all'):
        """Get bios attribute's available value
        :params attribute_name: Bios attribute name or 'all'
        :type attribute_name: string
        :returns: returns Dict of attribute_name's available value or List of all attributes
        """
        try:
            result = self.get_bios_attribute_metadata()
            if result['ret'] == False:
                return result
            bios_attribute_list = result['entries']["RegistryEntries"]["Attributes"]
            if attribute_name == 'all':
                return {'ret': True, 'entries': bios_attribute_list}
            for bios_attribute in bios_attribute_list:
                if attribute_name == bios_attribute['AttributeName']:
                    return {'ret': True, 'entries': bios_attribute}
            return {'ret': False, 'msg': "This bios attribute '%s' is not supported on this platform" % attribute_name}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bios attribute's available value. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bios_bootmode(self):
        """Get bios boot mode
        :returns: returns dict of bios boot mode when succeeded or error message when failed
        """
        result = {}
        try:
            result_bios = self.get_all_bios_attributes()
            if result_bios['ret'] == False:
                return result_bios

            attributes = result_bios['entries']
            bios_attribute = {}
            attribute_bootmode = None
            
            # firstly, search boot mode name which match with key exactly. 
            for attribute in attributes.keys():
                if attribute == "BootMode" or attribute == "SystemBootMode":
                    attribute_bootmode = attribute
                    break
            
            # secondly, if no key matchs perfectly, then search the attribute which contain boot mode name 
            if attribute_bootmode == None:
                for attribute in attributes.keys():
                    if "SystemBootMode" in attribute or "Boot Mode" in attribute or "Boot_Mode" in attribute:
                        attribute_bootmode = attribute
                        break
            if attribute_bootmode == None:
                return {'ret': False, 'msg': "Failed to find BootMode attribute in BIOS attributes."}
            bios_attribute[attribute_bootmode] = attributes[attribute_bootmode]
            return {'ret': True, 'entries': bios_attribute}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get boot mode. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_inventory(self):
        """Get BMC inventory    
        :returns: returns Dict of BMC inventory when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            
            # Get the BMC information
            bmc_info = {}
            result_manager = self.__get_url(manager_url)
            if result_manager['ret'] == True:
                bmc_info = propertyFilter(result_manager['entries'])
            else:
                return result_manager

            # Get Manager NetworkProtocol resource
            result = self.get_bmc_networkprotocol()
            if result['ret'] == True:
                bmc_info['NetworkProtocol'] = result['entries']

            # GET Manager SerialInterfaces resources
            result = self.get_bmc_serialinterfaces()
            if result['ret'] == True:
                bmc_info['SerialInterfaces'] = result['entries']

            # GET Manager EthernetInterfaces resources
            result = self.get_bmc_ethernet_interfaces()
            if result['ret'] == True:
                bmc_info['EthernetInterfaces'] = result['entries']

            # GET Manager HostInterfaces resources
            result = self.get_bmc_hostinterfaces()
            if result['ret'] == True:
                bmc_info['HostInterfaces'] = result['entries']

            return {'ret': True, 'entries': bmc_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_networkprotocol(self):
        """Get BMC network protocol which provide BMC's network services info.      
        :returns: returns Dict of BMC networkprotocol when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            result_network = self.__get_url(manager_url + '/NetworkProtocol')
            if result_network['ret'] == False:
                return result_network
            network_protocol = propertyFilter(result_network['entries'])
            return {'ret': True, 'entries': network_protocol}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's networkprotocol. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_serialinterfaces(self):
        """Get BMC Serial Interfaces    
        :returns: returns List of BMC serial interfaces when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()          
            result_serial = self.__get_collection(manager_url + '/SerialInterfaces')
            if result_serial['ret'] == False:
                return result_serial

            serial_info_list = []                      
            for member in result_serial['entries']:    
                serial_info = propertyFilter(member)
                serial_info_list.append(serial_info)
            return {'ret': True, 'entries': serial_info_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's serialinterfaces. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_ethernet_interfaces(self):
        """Get BMC ethernet interfaces
        :returns: returns List of BMC nic when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            result_ethernet = self.__get_collection(manager_url + '/EthernetInterfaces')
            if result_ethernet['ret'] == False:
                return result_ethernet

            ethernet_info_list = []
            for member in result_ethernet['entries']:                       
                ethernet_info = propertyFilter(member)
                ethernet_info_list.append(ethernet_info)
            return {'ret': True, 'entries': ethernet_info_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's ethernet interfaces. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_virtual_media(self):
        """Get BMC Serial Interfaces
        :returns: returns List of BMC serial interfaces when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()           
            result_vm = self.__get_collection(manager_url + '/VirtualMedia')
            if result_vm['ret'] == False:
                return result_vm

            vm_info_list = []                      
            for member in result_vm['entries']:    
                vm_info = propertyFilter(member)
                vm_info_list.append(vm_info)   
            return {'ret': True, 'entries': vm_info_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's virtual media. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_hostinterfaces(self):
        """Get BMC Host Interfaces    
        :returns: returns List of BMC host interfaces when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            result_hostinfs = self.__get_collection(manager_url + '/HostInterfaces')
            if result_hostinfs['ret'] == False:
                return result_hostinfs

            hostinf_info_list = propertyFilter(result_hostinfs['entries'])
            for member in hostinf_info_list:
                if 'HostEthernetInterfaces' in member.keys():
                    host_eth_url = member["HostEthernetInterfaces"]['@odata.id']
                    result_host_eth = self.__get_collection(host_eth_url)
                    if result_host_eth['ret'] == True: 
                        member['HostEthernetInterfaces'] = propertyFilter(result_host_eth['entries'])
                    else:
                        return result_host_eth
                if 'ManagerEthernetInterface' in member.keys():
                    manager_eth_url = member["ManagerEthernetInterface"]['@odata.id']
                    result_manager_eth = self.__get_url(manager_eth_url)
                    if result_manager_eth['ret'] == True: 
                        member['ManagerEthernetInterface'] = propertyFilter(result_manager_eth['entries'])
                    else:
                        return result_manager_eth
            return {'ret': True, 'entries': hostinf_info_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's host interfaces. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_ntp(self):
        """Get BMC inventory    
        :returns: returns Dict of bmc ntp when succeeded or error message when failed
        """
        result = {}
        try:
            result_network = self.get_bmc_networkprotocol()
            ntp = {}
            if result_network['ret'] == True:
                if "NTP" in result_network['entries']:
                    return {'ret': True, 'entries': result_network['entries']["NTP"]}
            else:
                return result_network
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc ntp. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_cpu_inventory(self):
        """Get cpu inventory
        :returns: returns List of all cpu inventory when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self.__find_system_resource()
            
            # Get the Processors collection
            result = self.__get_collection(system_url + '/Processors')
            if result['ret'] == False:
                return result
            
            list_cpu_info = []
            for member in result['entries']:
                if member["Status"]["State"] != 'Absent':
                    cpu_info = propertyFilter(member)
                    list_cpu_info.append(cpu_info)
            return {'ret': True, 'entries': list_cpu_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get cpu inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_memory_inventory(self, member_id=None):
        """Get cpu inventory
        :params member_id: Memory member id
        :type member_id: None or String of id
        :returns: returns List of all memory inventory when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self.__find_system_resource()

            # Get the Processors collection
            list_memory_info = []
            result = self.__get_collection(system_url + '/Memory')
            if result['ret'] == False:
                return result
            
            if member_id == None:
                for member in result['entries']:
                    if member["Status"]["State"] != 'Absent':
                        list_memory_info.append(member)
            else:
                for member in result['entries']:
                    if member_id == member['Id']:
                        list_memory_info.append(member)
                        break
                if len(list_memory_info) == 0:
                    return {'ret': False, 'msg': "Failed to find the memory with id %s. \
                              Please check if the id is correct." % member_id}

            # Filter property
            entries = []
            for member in list_memory_info:
                memory_info = propertyFilter(member)
                entries.append(memory_info)
            return {'ret': True, 'entries': entries}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get cpu inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_ethernet_interfaces(self):
        """Get system EthernetInterfaces
        :returns: returns List of all system EthernetInterfaces when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self.__find_system_resource()

            # Get the Processors collection
            result = self.__get_collection(system_url + '/EthernetInterfaces')
            
            if result['ret'] == False:
                return result
            
            list_nic_info = []
            for member in result['entries']:
                nic_info = {}
                for key in member.keys():
                    if key not in common_property_excluded and 'Redfish.Deprecated' not in key:
                        nic_info[key] = member[key]
                list_nic_info.append(nic_info)
            return {'ret': True, 'entries': list_nic_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system ethernet interfaces. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_storage(self):
        """Get system storage resource
        :returns: returns List of all system Storage when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self.__find_system_resource()

            # Get the Processors collection
            result = self.__get_collection(system_url + '/Storage')
            if result['ret'] == False:
                return result
            
            list_storage_info = []
            for member in result['entries']:
                storage_info = propertyFilter(member)

                if 'Drives' in member:
                    list_drives = []
                    for drive in member['Drives']:
                        result_drive = self.__get_url(drive['@odata.id'])
                        if result_drive['ret'] == True:
                            drive_info = propertyFilter(result_drive['entries'])
                            list_drives.append(drive_info)
                        else:
                            return result_drive
                    storage_info['Drives'] = list_drives

                if 'Volumes' in member:
                    result_volumes = self.__get_collection(member['Volumes']['@odata.id'])
                    list_volumes = []
                    if result_volumes['ret'] == True:
                        for volume in result_volumes['entries']:
                            volume_info = propertyFilter(volume)
                            list_volumes.append(volume_info)
                    else:
                        return result_volumes
                    storage_info['Volumes'] = list_volumes

                # Get storage Controller
                if 'StorageControllers' in member:
                    list_controller = []
                    for controller in member['StorageControllers']:
                        controller_info = propertyFilter(member)
                        list_controller.append(controller_info)
                    storage_info['StorageControllers'] = list_controller

                list_storage_info.append(storage_info)

            return {'ret': True, 'entries': list_storage_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system storage inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_simple_storage(self):
        """Get system's SimpleStorage inventory
        :returns: returns List of all system SimpleStorage when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self.__find_system_resource()

            # Get the Processors collection
            result = self.__get_collection(system_url + '/SimpleStorage')
            
            if result['ret'] == False:
                return result
            
            list_storage_info = []
            for member in result['entries']:
                storage_info = propertyFilter(member)
                list_storage_info.append(storage_info)
            return {'ret': True, 'entries': list_storage_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system SimpleStorage. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_storage_inventory(self):
        """Get storage inventory    
        :returns: returns Dict of storage inventory when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self.__find_system_resource()
            storage_info = {}
            
            # Get system Storage resource
            result = self.get_system_storage()
            if result['ret'] == True:
                storage_info['Storage'] = result['entries']
    
            # GET system SimpleStorage resources
            result = self.get_system_simple_storage()
            if result['ret'] == True:
                storage_info['SimpleStorage'] = result['entries']
    
            return {'ret': True, 'entries': storage_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get storage inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_power_state(self):
        """Get system's power state
        :returns: returns Dict of system power state when succeeded or error message when failed
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            result = self.__get_url(system_url)
            if result['ret'] == False:
                return result
            power_state = {}
            power_state['PowerState'] = result['entries']['PowerState']
            return {'ret': True, 'entries': power_state}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system power state. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_inventory(self):
        """Get System inventory    
        :returns: returns Dict of system inventory when succeeded or error message when failed
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            
            # Get the system information
            system_info = {}
            result_system = self.__get_url(system_url)
            if result_system['ret'] == True:
                system_info = propertyFilter(result_system['entries'], \
                    common_property_excluded + ['Processors', 'Memory', \
                    'SecureBoot', 'Storage', 'PCIeDevices', 'PCIeFunctions', \
                    'LogServices', 'PCIeDevices@odata.count', 'PCIeFunctions@odata.count'])
            else:
                return result_system

            # GET System EthernetInterfaces resources
            result = self.get_system_ethernet_interfaces()
            if result['ret'] == True:
                system_info['EthernetInterfaces'] = result['entries']

            return {'ret': True, 'entries': system_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_pci_inventory(self):
        """Get PCI devices inventory
        :returns: returns List of all PCI devices when succeeded or error message when failed
        """
        result = {}
        try:
            chassis_url = self.__find_chassis_resource()        
            result_pci = self.__get_collection(chassis_url + '/PCIeDevices')
            if result_pci['ret'] == False:
                return result_pci
            list_pci_info = propertyFilter(result_pci['entries'])

            for member in list_pci_info:
                if 'PCIeFunctions' in member:
                    result_pci_func = self.__get_collection(member['PCIeFunctions']['@odata.id'])
                    if result_pci_func['ret'] == False:
                        return result_pci_func
                    data_filtered = propertyFilter(result_pci_func['entries'])
                    member['PCIeFunctions'] = data_filtered
            return {'ret': True, 'entries': list_pci_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get chassis pci devices inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_nic_inventory(self):
        """Get network devices inventory
        :returns: returns List of all network devices when succeeded or error message when failed
        """
        
        # if failed, then try to get EthernetInterfaces' info from System.
        result = {}
        try:
            # firstly, try to get NetworkAdapter's info from Chassis.
            chassis_url = self.__find_chassis_resource()
            
            list_nic_info = []
            result_nic = self.__get_collection(chassis_url + '/NetworkAdapters')
            
            if result_nic['ret'] == True:
                list_nic_info = propertyFilter(result_nic['entries'], common_property_excluded, ['@Redfish'])
                for member in list_nic_info:
                    if 'NetworkDeviceFunctions' in member:
                        result_nic_func = self.__get_collection(member['NetworkDeviceFunctions']['@odata.id'])
                        if result_nic_func['ret'] == False:
                            return result_nic_func
                        data_filtered = propertyFilter(result_nic_func['entries'], common_property_excluded)
                        member['NetworkDeviceFunctions'] = data_filtered
                    if 'NetworkPorts' in member:
                        result_nic_ports = self.__get_collection(member['NetworkPorts']['@odata.id'])
                        if result_nic_ports['ret'] == False:
                            return result_nic_ports
                        data_filtered = propertyFilter(result_nic_ports['entries'], common_property_excluded)
                        member['NetworkPorts'] = data_filtered
                return {'ret': True, 'entries': list_nic_info}
            else:
                result = self.get_system_ethernet_interfaces()
                if result['ret'] == True:
                    return {'ret': True, 'entries': result['entries']}
                else:
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get chassis network devices inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_fan_inventory(self):
        """Get Fan devices inventory
        :returns: returns List of all Fan devices when succeeded or error message when failed
        """
        try:
            chassis_url = self.__find_chassis_resource()        
            result = self.__get_url(chassis_url + '/Thermal')
            if result['ret'] == False:
                return result
            list_fan_info = []
            if 'Fans' in result['entries']:
                list_fan_info = propertyFilter(result['entries']['Fans'], \
                                               common_property_excluded + \
                                               ['Oem'])
            return {'ret': True, 'entries': list_fan_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get fan devices inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_temperatures_inventory(self):
        """Get temperatures inventory
        :returns: returns List of all temperatures when succeeded or error message when failed
        """
        try:
            chassis_url = self.__find_chassis_resource()        
            result = self.__get_url(chassis_url + '/Thermal')
            if result['ret'] == False:
                return result
            list_temp_info = []
            if 'Temperatures' in result['entries']:
                list_temp_info = propertyFilter(result['entries']['Temperatures'])
            return {'ret': True, 'entries': list_temp_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get temperatures inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def __get_power_info(self, property=None):
        """Get property info from chassis power info 
        :returns: returns List of property info of power when succeeded or error message when failed
        """
        try:
            chassis_url = self.__find_chassis_resource()        
            result = self.__get_url(chassis_url + '/Power')
            if result['ret'] == False:
                return result
            
            if property == None:
                power_info = propertyFilter(result['entries'])
                return {'ret': True, 'entries': power_info}
            
            list_property_info = []
            if property in result['entries']:
                list_property_info = propertyFilter(result['entries'][property])
            return {'ret': True, 'entries': list_property_info}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get %s info. Error message: %s" % (property, repr(e))
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_psu_inventory(self):
        """Get PSU devices inventory
        :returns: returns List of all PSU devices when succeeded or error message when failed
        """         
        return self.__get_power_info('PowerSupplies')

    def get_power_redundancy(self):
        """Get power redundancy info
        :returns: returns List of power redundancy info when succeeded or error message when failed
        """
        
        return self.__get_power_info('Redundancy')

    def get_power_voltages(self):
        """Get power voltages info
        :returns: returns List of power voltages info when succeeded or error message when failed
        """
        
        return self.__get_power_info('Voltages')

    def get_power_metrics(self):
        """Get power metrics info
        :returns: returns Dict of power metrics of whole system when succeeded or error message when failed
        """
        power_metrics = {}
        result = self.__get_power_info('PowerControl')
        if result['ret'] == False:
            return result
        for member in result['entries']:
            if 'PowerMetrics' in member and 'Name' in member:
                #if 'Chassis' in member['Name'] or 'Server' in member['Name']:
                return {'ret': True, 'entries': member['PowerMetrics']}
        return {'ret': False, 'msg': "No power metrics exist."}

    def get_power_limit(self):
        """Get power limit info
        :returns: returns Dict of power limit of whole system when succeeded or error message when failed
        """
        power_metrics = {}
        result = self.__get_power_info('PowerControl')
        if result['ret'] == False:
            return result
        for member in result['entries']:
            if 'PowerLimit' in member:
                return {'ret': True, 'entries': member['PowerLimit']}
        return {'ret': False, 'msg': "No power limit exist."}

    #############################################
    # functions for setting.
    #############################################

    def get_system_reset_types(self):
        """Get system's reset types
        :returns: returns Dict of system reset types when succeeded or error message when failed
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            result = self.__get_url(system_url)
            if result['ret'] == False:
                return result
            if '@Redfish.ActionInfo' not in result['entries']["Actions"]["#ComputerSystem.Reset"]:
                return {'ret': False, 'msg': "Failed to get system reset types."}
            actioninfo_url = result['entries']['Actions']['#ComputerSystem.Reset']['@Redfish.ActionInfo']
            result = self.__get_url(actioninfo_url)
            if result['ret'] == False:
                return result
            if "Parameters" in result['entries']:
                for parameter in result['entries']["Parameters"]:
                    if ("Name" in parameter) and (parameter["Name"] == "ResetType"):
                        reset_types = {}
                        if "AllowableValues" in parameter:
                            reset_types["ResetType@Redfish.AllowableValues"] = parameter["AllowableValues"]
                            return {'ret': True, 'entries': reset_types}
            return {'ret': False, 'msg': "Failed to get system reset types."}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system reset types. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def set_system_power_state(self, reset_type):
        """Set system's power state, like on/off, restart.
        :params reset_type: reset system type, for example: 'On', 'GracefulShutdown', 'ForceRestart'.
        :type reset_type: string
        :returns: returns the result to set system power state. 
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            result = self.__get_url(system_url)
            if result['ret'] == False:
                return result
            target_url = result['entries']["Actions"]["#ComputerSystem.Reset"]["target"]
            post_body = {"ResetType": reset_type}
            post_response = self.post(target_url, body=post_body)
            # If Response return 200/OK, return successful , else print the response Error code
            if post_response.status in [200, 202, 204]:
                return {'ret': True, 'msg': "Succeed to set system '%s'." % reset_type}
            else:
                LOGGER.error(str(post_response))
                return {'ret': False, 'msg': "Failed to set system '%s'. Error code is %s. Error message is %s. " % \
                        (reset_type, post_response.status, post_response.text)}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to set system power state. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def set_bios_attribute(self, attribute_name, attribute_value):
        """Set bios attribute.
        :params attribute_name: Bios attribute name
        :type attribute_name: string
        :params attribute_value: new value of Bios attribute
        :type attribute_value: string
        :returns: returns the result to set bios attribute result
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            result = self.__get_url(system_url + '/Bios')
            if result['ret'] == False: 
                return result

            if "SettingsObject" in result['entries']['@Redfish.Settings'].keys():
                pending_url = result['entries']['@Redfish.Settings']['SettingsObject']['@odata.id']
            else:
                if 'Self' in system_url:
                    pending_url = bios_url + "/SD" # TSM
                else:
                    pending_url = bios_url + "/Pending" # XCC
            result = self.get_bios_attribute_available_value(attribute_name)
            if result['ret'] == False:
                return result
            
            parameter = {}
            attribute = result['entries']
            if attribute['Type'] == "Integer":
                try:
                    attribute_value = int(attribute_value)
                    parameter = {attribute_name: attribute_value}
                except:
                    result = {'ret': False, 'msg': "Please check the attribute value, this should be a number."}
                    return result
            elif attribute['Type'] == "Boolean":
                if attribute_value.upper() == "TRUE":
                    parameter = {attribute_name: True}
                elif attribute_value.upper() == "FALSE":
                    parameter = {attribute_name: False}
                else:
                    result = {'ret': False, 'msg': "Please check the attribute value, this value is 'true' or 'false'."}
                    return result
            else:
                parameter = {attribute_name: attribute_value}

            if parameter:
                attribute = {"Attributes": parameter}
            headers = {"If-Match": "*", "Content-Type": "application/json"}
            patch_response = self.patch(pending_url, headers = headers, body=attribute)
            if patch_response.status in [200, 204]:
                result = {'ret': True, 'msg': "Succeed to set '%s' to '%s'."% (attribute_name, attribute_value)}
            else:
                LOGGER.error(str(patch_response))
                result = {'ret': False, 'msg': "Failed to set '%s'. Error code is %s. Error message is %s. " % \
                        (attribute_name, patch_response.status, patch_response.text)}
            return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to set bios attribute. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bios_boot_order(self):
        """Get system boot order.
        :returns: returns Dict of system boot order info or error message.
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            bmc_type = 'TSM' if 'Self' in system_url else 'XCC'
            
            if bmc_type == 'XCC':
                result = self.__get_url(system_url)
                if result['ret'] == False: 
                    return result
                # for current products
                oem = result['entries']['Oem']
                if 'Lenovo' in oem and 'BootSettings' in oem['Lenovo']:
                    boot_settings_url = oem['Lenovo']['BootSettings']['@odata.id']
                    result = self.__get_collection(boot_settings_url)
                    if result['ret'] == False:
                        return result

                    boot_order_member = result['entries'][0]
                    data_filtered = propertyFilter(boot_order_member)
                    result = {'ret': True, 'entries': data_filtered}
                    return result

                # for next generation, TBU.
                if 'BootOrder' in result['entries']['Boot']:
                    pass
            
            if bmc_type == 'TSM':
                result = self.__get_url(system_url + '/Bios')
                if result['ret'] == False:
                    return result

                attributes = result['entries']['Attributes']
                attribute_name = ''
                attribute_value = ''
                if 'Q00999_Boot_Option_Priorities' in attributes:
                    attribute_name = 'Q00999_Boot_Option_Priorities'
                    attribute_value = attributes[attribute_name]
                elif 'Q00999 Boot Option Priorities' in attributes:
                    attribute_name = 'Q00999 Boot Option Priorities'
                    attribute_value = attributes[attribute_name]
                else:
                    rsult = {'ret': False, 'msg': "Failed to find boot options in Bios attributes."}
                    return result

                # Get BootOrderNext
                attribute_value_next = None
                bios_settings_url = result['entries']['@Redfish.Settings']['SettingsObject']['@odata.id']
                result = self.__get_url(bios_settings_url)
                if result['ret'] == False:
                    return result
                if 'Attributes' in result['entries'] and attribute_name in result['entries']['Attributes']:
                    attribute_value_next = result['entries']['Attributes'][attribute_name]

                # Parse attribute value string to get currnt/supported/next boot order settings
                boot_order_current = list()
                boot_order_supported = list()
                for boot_order_item in attribute_value.split(';'):
                    boot_order_name = boot_order_item.split(',')[0]
                    boot_order_supported.append(boot_order_name)
                    if 'true' in boot_order_item:
                        boot_order_current.append(boot_order_name)
                if attribute_value_next is None:
                    boot_order_next = boot_order_current
                else:
                    boot_order_next = list()
                    for boot_order_item in attribute_value_next.split(';'):
                        boot_order_name = boot_order_item.split(',')[0]
                        if 'true' in boot_order_item:
                            boot_order_next.append(boot_order_name)

                # Set result
                boot_order_info = {}
                boot_order_info['BootOrderNext'] = boot_order_next
                boot_order_info['BootOrderSupported'] = boot_order_supported
                boot_order_info['BootOrderCurrent'] = boot_order_current
                result = {'ret': True, 'entries': boot_order_info}
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system boot order. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def set_bios_boot_order(self, bootorder):
        """Set system boot order.
        :params bootorder: Specify the bios boot order list, like: ["ubuntu", "CD/DVD Rom", "Hard Disk", "USB Storage"]
        :type bootorder: list
        :returns: returns the result to set system boot order result
        """
        result = {}
        try:
            system_url = self.__find_system_resource()
            bmc_type = 'TSM' if 'Self' in system_url else 'XCC'
            
            result = self.__get_url(system_url)
            if result['ret'] == False: 
                return result

            if bmc_type == 'XCC':
                # for current products
                oem = result['entries']['Oem']
                if 'Lenovo' in oem and 'BootSettings' in oem['Lenovo']:
                    boot_settings_url = oem['Lenovo']['BootSettings']['@odata.id']
                    result = self.__get_collection(boot_settings_url)
                    if result['ret'] == False:
                        return result

                    boot_order_member = result['entries'][0]
                    boot_order_url = boot_order_member['@odata.id']
                    boot_order_supported = boot_order_member['BootOrderSupported']
                    for boot in bootorder:
                        if boot not in boot_order_supported:
                            result = {'ret': False, 'msg': "Invalid boot option %s. You can specify one or more boot option from list: %s." %(boot, boot_order_supported)}
                            return result

                    # Set the boot order next via patch request
                    body = {"BootOrderNext": bootorder}
                    patch_response = self.patch(boot_order_url, body=body)
                    
                    if patch_response.status in [200]:
                        boot_order_next = patch_response.dict["BootOrderNext"]
                        result = {'ret': True, 'msg': "Succeed to set boot order '%s'. New boot order will take effect on next startup."%(boot_order_next)}
                        return result
                    else:
                        LOGGER.error(str(patch_response))
                        result = {'ret': False, 'msg': "Failed to set '%s'. Error code is %s. Error message is %s. " % \
                                (attribute_name, patch_response.status, patch_response.text)}

                # for next generation, TBU.
                if 'BootOrder' in result['entries']['Boot']:
                    pass
            
            if bmc_type == 'TSM':
                result = self.get_all_bios_attributes()
                if result['ret'] == False:
                    return result

                attribute_name = ''
                attribute_value = ''
                if 'Q00999_Boot_Option_Priorities' in result['entries']:
                    attribute_name = 'Q00999_Boot_Option_Priorities'
                    attribute_value = result['entries'][attribute_name]
                elif 'Q00999 Boot Option Priorities' in result['entries']:
                    attribute_name = 'Q00999 Boot Option Priorities'
                    attribute_value = result['entries'][attribute_name]
                else:
                    result = {'ret': False, 'msg': "Failed to find boot options in bios attributes."}
                    return result

                # Get supported boot order list
                boot_order_supported = list()
                org_boot_order_struct_list = attribute_value.split(';')
                for boot_order_struct in org_boot_order_struct_list:
                    boot_order_name = boot_order_struct.split(',')[0]
                    boot_order_supported.append(boot_order_name)

                # Set payload body
                body = {}
                new_boot_order_struct_list = list()
                for boot in bootorder:
                    # If input bootorder is not supported, prompt error message
                    if boot not in boot_order_supported:
                        result = {'ret': False, 'msg': "Invalid boot option %s. You can specify one or more boot option from list: %s." %(boot, boot_order_supported)}
                        return result
                    # Add enabled bootorder list
                    for boot_order_struct in org_boot_order_struct_list:
                        boot_order_name = boot_order_struct.split(',')[0]
                        if boot == boot_order_name:
                            newstruct = boot_order_struct.replace('false', 'true')
                            if newstruct not in new_boot_order_struct_list:
                                new_boot_order_struct_list.append(newstruct)
                # Add disabled bootorder list
                for boot_order_struct in org_boot_order_struct_list:
                    boot_order_name = boot_order_struct.split(',')[0]
                    if boot_order_name not in bootorder:
                        newstruct = boot_order_struct.replace('true', 'false')
                        if newstruct not in new_boot_order_struct_list:
                            new_boot_order_struct_list.append(newstruct)
                new_boot_order_struct_string = ''
                for item in new_boot_order_struct_list:
                    new_boot_order_struct_string = new_boot_order_struct_string + item + ';'
                result = self.set_bios_attribute(attribute_name, new_boot_order_struct_string)
                if result['ret'] == False:
                    return result
                else:
                    result = {'ret': True, 'msg': "Succeed to set boot order. New boot order will take effect on next startup."}
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to set boot order. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def set_bios_bootmode(self, bootmode):
        """Set bios bootmode.
        :params bootmode: new value of Bios attribute
        :type bootmode: string.
        :returns: returns the result to set bios bootmode result
        """
        result = self.get_bios_bootmode()
        if result['ret'] == False:
            return result

        attribute_name = list(result['entries'].keys())[0]
        result = self.set_bios_attribute(attribute_name, bootmode)
        return result

    def lenovo_get_bmc_users(self):
        """Get bmc user accounts
        :returns: returns List of bmc user accounts.
        """
        result = {}
        try:
            result = self.__get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account_info_list = []
            for member in result['entries']:
                if "Links" in member and "Role" in member["Links"]:
                    accounts_role_url = member["Links"]["Role"]["@odata.id"]
                    # Get the BMC user privileges info
                    result_role = self.__get_url(accounts_role_url)
                    if result_role['ret'] == False:
                        return result_role
                    privileges = result_role['entries']["AssignedPrivileges"]
                    member['AssignedPrivileges'] = privileges
                    if "OemPrivileges" in result_role['entries']:
                        oem_privileges = result_role['entries']["OemPrivileges"]
                        member['OemPrivileges'] = oem_privileges
                    filtered_data = propertyFilter(member,strings_excluded=['Links'])
                    account_info_list.append(filtered_data)
            return {'ret': True, 'entries': account_info_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's user accounts. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def __check_bmc_type(self):
        manager_url = self.__find_manager_resource()
        bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
        return bmc_type

    def lenovo_create_bmc_user(self, username, password, authority):
        """Create new bmc user account
        :params username: new  username
        :type username: string
        :params password: new password
        :type password: string
        :params authority: user authority list, like ['Supervisor'] or ['UserAccountManagement', 'RemoteConsoleAccess']
        :type authority: list
        :returns: returns result of creating bmc user account.
        """
        result = {}
        try:
            accounts_url = '/redfish/v1/AccountService/Accounts'
            bmc_type = self.__check_bmc_type()
            # for TSM (SR635/655)
            if bmc_type == 'TSM':
                # Set user privilege
                # for TSM, only accept 'Supervisor', 'Administrator', 'Operator' and 'ReadOnly'
                rolename = ""
                if "Supervisor" in authority or "Administrator" in authority:
                    rolename = "Administrator"
                elif "Operator" in authority:
                    rolename = "Operator"
                elif "ReadOnly" in authority:
                    rolename = "ReadOnly"
                else:
                    rolename = authority[0]
                #create new user account
                headers = None
                parameter = {
                    "Password": password,
                    "Name": username,
                    "UserName": username,
                    "RoleId":rolename
                    }
                post_response = self.post(accounts_url, body=parameter, headers=headers)
                if post_response.status in [200, 201, 202, 204]:
                    return {'ret': True, 'msg': "Succeed to create new user '%s'." % username}
                else:
                    LOGGER.error(str(post_response))
                    return {'ret': False, 'msg': "Failed to create new user '%s'. Error code is %s. Error message is %s. " % \
                            (username, post_response.status, post_response.text)}
            
            # for XCC
            result = self.__get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account_url = ''
            for member in result['entries']:
                if member['UserName'] == username:
                    return {'ret': False, 'msg': "Failed to create new user. User '%s' existed." % username}
                if member['UserName'] != '':
                    continue
                
                # found first empty account
                account_url = member['@odata.id']
                role_url = member["Links"]["Role"]["@odata.id"]
                #result_role = self.__get_url(roleuri)
                parameter = {
                    "OemPrivileges": authority
                }
                patch_response = self.patch(role_url, body=parameter)
                if patch_response.status not in [200, 204]:
                    result = {'ret': False, 'msg': "Failed to set the privileges. \
                              Error code is %s. Error message is %s. " % \
                              (post_response.status, post_response.text)}
                    return result
                if "@odata.etag" in member:
                    etag = member['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}
                parameter = {
                    "Password": password,
                    "UserName": username
                    }
                patch_response = self.patch(account_url, body=parameter, headers=headers)
                if patch_response.status in [200, 204]:
                    result = {'ret': True, 'msg': "Succeed to create new user. Account id is '%s'." % member['Id']}
                    return result
                else:
                    LOGGER.error(str(patch_response))
                    result = {'ret': False, 'msg': "Failed to create new user '%s'. Error code is %s. Error message is %s. " % \
                             (username, patch_response.status, patch_response.text)}
                    return result
            if account_url == '':
                return {'ret': False, 'msg': "Accounts is full."}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get bmc's user accounts. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_delete_bmc_user(self, username):
        """delete one bmc user account
        :params username: bmc user name deleted
        :type username: string
        :returns: returns result of deleting bmc user account.
        """
        result = {}
        try:
            bmc_type = self.__check_bmc_type()
            result = self.__get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account_url = ''
            for member in result['entries']:
                if member["UserName"] == username:
                    account_url = member["@odata.id"]
                    if "@odata.etag" in member:
                        etag = member['@odata.etag']
                    else:
                        etag = ""

                    response = {}
                    if bmc_type == 'TSM':  # for TSM (SR635/655)
                        headers = {"If-Match": "*" }
                        response = self.delete(account_url, headers=headers)
                    else: # for XCC
                        headers = {"If-Match": etag}
                        parameter = {
                            "Enabled": False,
                            "UserName": ""
                        }
                        response = self.patch(account_url, body=parameter, headers=headers)
                                            
                    if response.status in [200, 204]:
                        result = {'ret': True, 'msg': "Account '%s' was deleted successfully." % username}
                        return result
                    else:
                        LOGGER.error(str(response))
                        result = {'ret': False, 'msg': "Failed to delete user '%s'. Error code is %s. Error message is %s. " % \
                                 (username, response.status, response.text)}
                        return result
            if account_url == '':
                result = {'ret': False, 'msg': "The user '%s' specified does not exist." % username}
                LOGGER.error(result['msg'])
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to delete bmc's user. Error message: %s" % repr(e)
            LOGGER.error(msg)
            result = {'ret': False, 'msg': msg}
            return result

    def set_bmc_networkprotocol(self, service, enabled=None, port=None):
        """enable or disable one bmc network service or change the service port numbers.      
        :params service: network service of bmc. support:["HTTPS","SSDP","SSH","SNMP","IPMI","VirtualMedia"]
        :type service: string
        :params enabled: Disable(0) or enable(1) bmc service
        :type enabled: int
        :params port: network service's port
        :type port: int
        :returns: returns the result to set bmc's network service
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            result = self.__get_url(manager_url + '/NetworkProtocol')
            if result['ret'] == False:
                return result
            
            if service not in result['entries']:
                result = {'ret': False, 'msg': "Please check service name '%s', which does not exist." % service}
                return result
            
            if "@odata.etag" in result['entries']:
                etag = result['entries']['@odata.etag']
            else:
                etag = ""
            headers = {"If-Match": etag}
            
            if service in ["IPMI", "SSDP", "DHCPv6", "NTP"]:
                if enabled == None:
                    return {'ret': False, 'msg': "Please specify enable parameter."}
                body = {service:{"ProtocolEnabled":bool(int(enabled))}}
            elif service in ["SSH", "SNMP"]:
                if enabled == None or port == None: 
                    return {'ret': False, 'msg': "Please specify enable parameter."}
                body = {service:{"ProtocolEnabled":bool(int(enabled)),"Port":port}}
            elif service in ["HTTPS", "VirtualMedia"]:
                if port == None:
                    return {'ret': False, 'msg': "Please specify port parameter."}
                body = {service:{"Port":port}}
            else:
                result = {'ret': False, 'msg': "Please check if service name is in the %s." % result['entries'].keys()}
                return result
            response = self.patch(manager_url + '/NetworkProtocol', body=body, headers=headers)
            if response.status in [200,204]:
                result = {'ret': True, 'msg': "Succeed to set bmc's network service %s." % service}
                return result
            else:
                LOGGER.error(str(response))
                result = {'ret': False, 'msg': "Failed to set bmc's network service %s. Error code is %s. Error message is %s. " % \
                         (service, response.status, response.text)}
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to set bmc's network service. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_firmware_inventory(self):
        """Get firmware inventory
        :returns: returns List of firmwares when succeeded or error message when failed
        """
        try:
            result = self.__get_url('/redfish/v1/UpdateService')
            if result['ret'] == False:
                return result

            fw_url = result['entries']['FirmwareInventory']['@odata.id']
            result = self.__get_collection(fw_url)
            if result['ret'] == False:
                return result

            list_fw_inventory = propertyFilter(result['entries'])
            result = {'ret': True, 'entries': list_fw_inventory}
            return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get firmware inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def __task_monitor(self, task_uri, wait_time=10):
        """Monitor task status
        :params task_uri: task uri for tracking the update status.
        :type task_uri: string
        :params wait_time: maximum time(minutes) to wait the task complete. 
        :type wait_time: int
        :returns: returns the task state and task information.
        """
        END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended", "Done", "Failed when Flashing Image."]
        time_start=time.time()
        print("Start to refresh the firmware, please wait about 3~10 minutes...")
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
                        result = {'ret': True, 'msg': "Succeed to update the firmware.", 'entries': response_task_uri.dict}
                    else:
                        result = {'ret': False, 'msg': "Failed to update firmware.", 'entries': response_task_uri.dict}
                    return result
                else:
                    time_now = time.time()
                    # wait for max 10 minutes to avoid endless loop.
                    wait_seconds = wait_time * 60
                    if time_now - time_start > wait_seconds:
                        result = {'ret': False, 'msg':  "It is over %s minutes to update the firmware." % wait_time, 'entries': response_task_uri.dict}
                        return result
                    time.sleep(10)
            else:
                result = {'ret': False, 'msg': "Failed to get the info of task '%s'. Error code is %s. Error message is %s. " % \
                          (task_uri, response_task_uri.status, response_task_uri.text)}
                LOGGER.error(result['msg'])
                return result

    def lenovo_update_firmware(self, image, target=None, fsprotocol='HTTPPUSH', fsip=None, fsdir=None, fsusername=None, fspassword=None):
        """Update firmware.
        :params targets: target. For XCC: only 'BMC-Backup'. For TSM: only 'BMC' or 'UEFI'.
        :type targets: string
        :params image: image's file path or url
        :type image: string
        :params fsprotocol: transfer protocol, like HTTPPUSH, SFTP
        :type fsprotocol: string
        :params fsip: file server ip, like sftp or tftp server ip
        :type fsip: string
        :params fsusername: username to access sftp file server 
        :type fsusername: string
        :params fspassword: password to access sftp file server
        :type fspassword: string
        :params fsdir: full path of dir on file server(sftp/tftp) or local machine(httppush), under which image is saved 
        :type fsdir: string
        :returns: returns the result of firmware updating
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self.__get_url('/redfish/v1/UpdateService')
            if result['ret'] == False:
                return result

            if bmc_type == 'XCC':
                if target != None and target.lower() == "bmc-backup":
                    target = "/redfish/v1/UpdateService/FirmwareInventory/BMC-Backup"
                else:
                    target = None
                # Update firmware via local payload
                if fsprotocol.lower() == "httppush":
                    firmware_update_url =  self.get_base_url() + result['entries']["HttpPushUri"]
                    if fsdir == None or fsdir == '':
                        file_path = os.getcwd()+ os.sep + image
                    else:
                        if os.path.isdir(fsdir):
                            file_path = fsdir + os.sep + image
                        else:
                            result = {'ret': False, 'msg': "The path '%s' doesn't exist, please check if 'fsdir' is correct." % fsdir}
                            return result
                    if (not os.path.exists(file_path)):
                        result = {'ret': False, 'msg': "File '%s' does not exist." % file_path}
                        return result

                    headers = {"Content-Type":"application/octet-stream"}
                    headers['X-Auth-Token'] = self.get_session_key()
                    files = {'data-binary':open(file_path,'rb')}
                    if self.__cafile is not None and self.__cafile != "":
                        response = requests.post(firmware_update_url, headers=headers, files=files, verify=self.__cafile)
                    else:
                        # Ignore SSL Certificates
                        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                        response = requests.post(firmware_update_url, headers=headers, files=files, verify=False)
                    response_code = response.status_code
                else: # sftp/tftp
                    firmware_update_url = result['entries']['Actions']['#UpdateService.SimpleUpdate']['target']
                    # Update firmware via file server
                    # Define an anonymous function formatting parameter
                    dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                    fsdir = dir(fsdir)

                    if fsprotocol.lower() not in ["sftp", "tftp"]:
                        result = {'ret': False, 'msg': "Protocol only supports HTTPPUSH, SFTP and TFTP."}
                        return result

                    # Build an dictionary to store the request body
                    body = {"ImageURI": fsip + fsdir + "/" + image}
                    if fsusername and fsusername != '':
                        body['Username'] = fsusername
                    if fspassword and fspassword != '':
                        body['Password'] = fspassword
                    if target and target != '':
                        body["Targets"] = [target]
                    if fsprotocol and fsprotocol != '':
                        body["TransferProtocol"] = fsprotocol.upper()
                    response = self.post(firmware_update_url, body=body)
                    response_code = response.status

                if response_code in [200, 204]:
                    result = {'ret': True, 'msg': "Succeed to update the firmware."}
                    return result
                elif response_code == 202:
                    if fsprotocol.lower() == "httppush":
                        task_uri = response.json()['@odata.id']
                    else:
                        task_uri = response.dict['@odata.id']
                    result = self.__task_monitor(task_uri)
                    # Delete task
                    self.delete(task_uri, None)
                    return result
                else:
                    result = {'ret': False, 'msg': "Failed to update '%s'. Error code is %s. Error message is %s. " % \
                              (image, response_code, response.text)}
                    LOGGER.error(result['msg'])
                    return result

            if bmc_type == 'TSM':
                if "MultipartHttpPushUri" in result['entries'] and fsprotocol.upper() == "HTTPPUSH":
                    if target == None or target.upper() not in ['BMC', 'UEFI']:
                        result = {'ret': False, 'msg': "You must specify the target: BMC or UEFI."}
                        return result
                    elif target.upper() == "BMC":
                        oem_parameters = {"FlashType": "HPMFwUpdate", "UploadSelector": "Default"}
                    else: # UEFI
                        oem_parameters = {"FlashType": "UEFIUpdate", "UploadSelector": "Default"}

                    if fsdir == None or fsdir == '':
                        fsdir = os.getcwd()
                    file_path = fsdir + os.sep + image
                    if (not os.path.exists(file_path)):
                        result = {'ret': False, 'msg': "File '%s' does not exist." % file_path}
                        return result

                    multipart_uri = self.get_base_url() + result['entries']["MultipartHttpPushUri"]
                    parameters = {"Targets": [manager_url]}
                    
                    # Create temporary files to write to the OEM value
                    parameters_file = os.getcwd() + os.sep + "parameters.json"
                    oem_parameters_file = os.getcwd() + os.sep + "oem_parameters.json"
                    with open(parameters_file, 'w') as f:
                        f.write(json.dumps(parameters))
                    with open(oem_parameters_file, 'w') as f:
                        f.write(json.dumps(oem_parameters))

                    f_parameters = open(parameters_file, 'rb')
                    f_oem_parameters = open(oem_parameters_file, 'rb')
                    # Specify the parameters required to update the firmware
                    files = {'UpdateParameters': ("parameters.json", f_parameters, 'application/json'),
                             'OemParameters': ("oem_parameters.json", f_oem_parameters, 'application/json'),
                             'UpdateFile': (image, open(file_path, 'rb'), 'multipart/form-data')}

                    # Send a post command through requests to update the firmware
                    # Ignore SSL Certificates
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  
                    print("Start to upload the image, may take about 3~10 minutes...")
                    firmware_update_url = multipart_uri
                    headers = {}
                    if self.__auth == 'session':
                        headers["X-Auth-Token"] = self.get_session_key()
                        response = requests.post(multipart_uri, headers=headers, files=files, verify=False)
                    else:
                        headers["Authorization"] = self.get_authorization_key()
                        response = requests.post(multipart_uri, headers=headers, files=files, verify=False)
                    response_code = response.status_code
                    
                    f_parameters.close()
                    f_oem_parameters.close()
                    # Delete temporary files if they exist
                    if os.path.exists(parameters_file):
                        os.remove(parameters_file)
                    if os.path.exists(oem_parameters_file):
                        os.remove(oem_parameters_file)

                    if response_code in [200, 202, 204]:
                        # For BMC update, BMC will restart automatically, the session connection will be disconnected, user have to wait BMC to restart.
                        # For UEFI update, the script can monitor the update task via BMC. 
                        if target.upper() == "BMC":
                            task_uri = response.headers['Location']
                            print("BMC update task is: %s." % task_uri)
                            result = {'ret': True, 'msg': 'Succeed to update bmc, wait about 5 minutes for bmc to restart.', 'task': task_uri}
                            return result
                        else:
                            task_uri = response.headers['Location']
                            result = self.__task_monitor(task_uri)
                            self.delete(task_uri, None)
                            return result
                    else:
                        result = {'ret': False, 'msg': "Failed to update '%s'. Error code is %s. Error message is %s. " % \
                                  (image, response_code, response.text)}
                        LOGGER.error(result['msg'])
                        return result
                else:
                    result = {'ret': False, 'msg': "This product only supports HTTPPUSH protocol."}
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to update the firmware. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_export_ffdc(self, image, target=None, fsprotocol='HTTPPUSH', fsip=None, fsdir=None, fsusername=None, fspassword=None):
        """Update firmware.
        :params targets: target. For XCC: only 'BMC-Backup'. For TSM: only 'BMC' or 'UEFI'.
        :type targets: string
        :params image: image's file path or url
        :type image: string
        :params fsprotocol: transfer protocol, like HTTPPUSH, SFTP
        :type fsprotocol: string
        :params fsip: file server ip, like sftp or tftp server ip
        :type fsip: string
        :params fsusername: username to access sftp file server 
        :type fsusername: string
        :params fspassword: password to access sftp file server
        :type fspassword: string
        :params fsdir: full path of dir on file server(sftp/tftp) or local machine(httppush), under which image is saved 
        :type fsdir: string
        :returns: returns the result of firmware updating
        """
        result = {}
        try:
            manager_url = self.__find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self.__get_url('/redfish/v1/UpdateService')
            if result['ret'] == False:
                return result

            if bmc_type == 'XCC':
                if target != None and target.lower() == "bmc-backup":
                    target = "/redfish/v1/UpdateService/FirmwareInventory/BMC-Backup"
                else:
                    target = None
                # Update firmware via local payload
                if fsprotocol.lower() == "httppush":
                    firmware_update_url =  self.get_base_url() + result['entries']["HttpPushUri"]
                    if fsdir == None or fsdir == '':
                        file_path = os.getcwd()+ os.sep + image
                    else:
                        if os.path.isdir(fsdir):
                            file_path = fsdir + os.sep + image
                        else:
                            result = {'ret': False, 'msg': "The path '%s' doesn't exist, please check if 'fsdir' is correct." % fsdir}
                            return result
                    if (not os.path.exists(file_path)):
                        result = {'ret': False, 'msg': "File '%s' does not exist." % file_path}
                        return result

                    headers = {"Content-Type":"application/octet-stream"}
                    headers['X-Auth-Token'] = self.get_session_key()
                    files = {'data-binary':open(file_path,'rb')}
                    if self.__cafile is not None and self.__cafile != "":
                        response = requests.post(firmware_update_url, headers=headers, files=files, verify=self.__cafile)
                    else:
                        # Ignore SSL Certificates
                        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                        response = requests.post(firmware_update_url, headers=headers, files=files, verify=False)
                    response_code = response.status_code
                else: # sftp/tftp
                    firmware_update_url = result['entries']['Actions']['#UpdateService.SimpleUpdate']['target']
                    # Update firmware via file server
                    # Define an anonymous function formatting parameter
                    dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                    fsdir = dir(fsdir)

                    if fsprotocol.lower() not in ["sftp", "tftp"]:
                        result = {'ret': False, 'msg': "Protocol only supports HTTPPUSH, SFTP and TFTP."}
                        return result

                    # Build an dictionary to store the request body
                    body = {"ImageURI": fsip + fsdir + "/" + image}
                    if fsusername and fsusername != '':
                        body['Username'] = fsusername
                    if fspassword and fspassword != '':
                        body['Password'] = fspassword
                    if target and target != '':
                        body["Targets"] = [target]
                    if fsprotocol and fsprotocol != '':
                        body["TransferProtocol"] = fsprotocol.upper()
                    response = self.post(firmware_update_url, body=body)
                    response_code = response.status

                if response_code in [200, 204]:
                    result = {'ret': True, 'msg': "Succeed to update the firmware."}
                    return result
                elif response_code == 202:
                    if fsprotocol.lower() == "httppush":
                        task_uri = response.json()['@odata.id']
                    else:
                        task_uri = response.dict['@odata.id']
                    result = self.__task_monitor(task_uri)
                    # Delete task
                    self.delete(task_uri, None)
                    return result
                else:
                    result = {'ret': False, 'msg': "Failed to update '%s'. Error code is %s. Error message is %s. " % \
                              (image, response_code, response.text)}
                    LOGGER.error(result['msg'])
                    return result

            if bmc_type == 'TSM':
                if "MultipartHttpPushUri" in result['entries'] and fsprotocol.upper() == "HTTPPUSH":
                    if target == None or target.upper() not in ['BMC', 'UEFI']:
                        result = {'ret': False, 'msg': "You must specify the target: BMC or UEFI."}
                        return result
                    elif target.upper() == "BMC":
                        oem_parameters = {"FlashType": "HPMFwUpdate", "UploadSelector": "Default"}
                    else: # UEFI
                        oem_parameters = {"FlashType": "UEFIUpdate", "UploadSelector": "Default"}

                    if fsdir == None or fsdir == '':
                        fsdir = os.getcwd()
                    file_path = fsdir + os.sep + image
                    if (not os.path.exists(file_path)):
                        result = {'ret': False, 'msg': "File '%s' does not exist." % file_path}
                        return result

                    multipart_uri = self.get_base_url() + result['entries']["MultipartHttpPushUri"]
                    parameters = {"Targets": [manager_url]}
                    
                    # Create temporary files to write to the OEM value
                    parameters_file = os.getcwd() + os.sep + "parameters.json"
                    oem_parameters_file = os.getcwd() + os.sep + "oem_parameters.json"
                    with open(parameters_file, 'w') as f:
                        f.write(json.dumps(parameters))
                    with open(oem_parameters_file, 'w') as f:
                        f.write(json.dumps(oem_parameters))

                    f_parameters = open(parameters_file, 'rb')
                    f_oem_parameters = open(oem_parameters_file, 'rb')
                    # Specify the parameters required to update the firmware
                    files = {'UpdateParameters': ("parameters.json", f_parameters, 'application/json'),
                             'OemParameters': ("oem_parameters.json", f_oem_parameters, 'application/json'),
                             'UpdateFile': (image, open(file_path, 'rb'), 'multipart/form-data')}

                    # Send a post command through requests to update the firmware
                    # Ignore SSL Certificates
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  
                    print("Start to upload the image, may take about 3~10 minutes...")
                    firmware_update_url = multipart_uri
                    headers = {}
                    if self.__auth == 'session':
                        headers["X-Auth-Token"] = self.get_session_key()
                        response = requests.post(multipart_uri, headers=headers, files=files, verify=False)
                    else:
                        headers["Authorization"] = self.get_authorization_key()
                        response = requests.post(multipart_uri, headers=headers, files=files, verify=False)
                    response_code = response.status_code
                    
                    f_parameters.close()
                    f_oem_parameters.close()
                    # Delete temporary files if they exist
                    if os.path.exists(parameters_file):
                        os.remove(parameters_file)
                    if os.path.exists(oem_parameters_file):
                        os.remove(oem_parameters_file)

                    if response_code in [200, 202, 204]:
                        # For BMC update, BMC will restart automatically, the session connection will be disconnected, user have to wait BMC to restart.
                        # For UEFI update, the script can monitor the update task via BMC. 
                        if target.upper() == "BMC":
                            task_uri = response.headers['Location']
                            print("BMC update task is: %s." % task_uri)
                            result = {'ret': True, 'msg': 'Succeed to update bmc, wait about 5 minutes for bmc to restart.', 'task': task_uri}
                            return result
                        else:
                            task_uri = response.headers['Location']
                            result = self.__task_monitor(task_uri)
                            self.delete(task_uri, None)
                            return result
                    else:
                        result = {'ret': False, 'msg': "Failed to update '%s'. Error code is %s. Error message is %s. " % \
                                  (image, response_code, response.text)}
                        LOGGER.error(result['msg'])
                        return result
                else:
                    result = {'ret': False, 'msg': "This product only supports HTTPPUSH protocol."}
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to update the firmware. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}







# TBU
if __name__ == "__main__":
    # initiate LenovoRedfishClient object, specify ip/user/password/authentication.
    #lenovo_redfish = LenovoRedfishClient('10.245.39.153', 'renxulei', 'PASSW0RD12q', auth='basic')
    lenovo_redfish = LenovoRedfishClient('10.245.39.251', 'renxulei', 'PASSW0RD12q', auth='session')

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

    # XCC:
    #fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\Intel"
    #image = "lnvgy_fw_uefi_ive160g-2.70_anyos_32-64.uxz"
    #image = "lnvgy_fw_xcc_cdi358g-4.80_anyos_noarch.uxz"
    #result = lenovo_redfish.lenovo_update_firmware(image=image, fsdir=fsdir)
    #result = lenovo_redfish.lenovo_update_firmware(image=image, fsdir='/home/sftp_root/upload', fsprotocol='SFTP', fsip='10.245.100.159', fsusername='mysftp', fspassword='wlylenovo')    

    # AMD
    #image_uefi = "lnvgy_fw_uefi_cfe117k-5.10_anyos_32-64.rom"
    #image_bmc = "lnvgy_fw_bmc_ambt11n-2.53_anyos_arm.hpm"
    #fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\AMD"
    #result = lenovo_redfish.lenovo_update_firmware(image=image_uefi, target='UEFI', fsdir=fsdir)
    #result = lenovo_redfish.lenovo_update_firmware(image=image_bmc, target='BMC', fsdir=fsdir)

    result = lenovo_redfish.get_firmware_inventory()
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