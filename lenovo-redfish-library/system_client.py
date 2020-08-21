###
#
# Lenovo Redfish Client - System Client
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
import traceback 

from redfish_base import RedfishBase
from utils import *
from utils import add_common_parameter
from utils import parse_common_parameter

class SystemClient(RedfishBase):
    """A client for managing system"""

    def __init__(self, ip='', username='', password='',
                 configfile='config.ini', auth=''):
        """Initialize SystemClient"""

        super(SystemClient, self).__init__(
            ip=ip, username=username, password=password, 
            configfile=configfile, auth=auth
        )

    #############################################
    # functions for getting information.
    #############################################

    def get_all_bios_attributes(self, type='current'):
        """Get all bios attribute
        :params type: 'current' setting or 'pending' setting(default is 'current')
        :type type: string
        :returns: returns dict of all bios attributes when succeeded or error message when failed
        """

        if type not in ['current', 'pending']:
            return {'ret': False, 'msg': "Please specify parameter with 'current' or 'pending'."}

        result = {}
        try:
            system_url = self._find_system_resource()
            result_bios = self._get_url(system_url + '/Bios')
            if result_bios['ret'] == False:
                return result_bios

            if type == "current":
                # Get the bios url resource
                return {'ret': True, 'entries': result_bios['entries']['Attributes']}
            else:
                # Get pending url
                pending_url = result_bios['entries']['@Redfish.Settings']['SettingsObject']['@odata.id']
                result_pending_url = self._get_url(pending_url)
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
            system_url = self._find_system_resource()
            result = self._get_url(system_url + '/Bios')

            if result['ret'] == False:
                return result
    
            # Get used AttributeRegistry from Bios url
            attribute_registry = result['entries']['AttributeRegistry']

            # Find the AttributeRegistry json file uri from Registries
            registry_url = "/redfish/v1/Registries"
            result = self._get_url(registry_url)
            if result['ret'] != True:
                return result
            bios_registry_url = None
            members_list = result['entries']['Members']
            for registry in members_list:
                if attribute_registry in registry['@odata.id']:
                    bios_registry_url = registry['@odata.id']
            if bios_registry_url is None:
                return {'ret': False, 'msg': "Can not find %s in Registries" % (attribute_registry)}

            result = self._get_url(bios_registry_url)
            if result['ret'] != True:
                return result
            bios_registry_json_url = result['entries']['Location'][0]['Uri']

            # Download the AttributeRegistry json file
            result = self._get_url(bios_registry_json_url)
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

    def get_system_boot_order(self):
        """Get system boot order.
        :returns: returns Dict of system boot order info or error message.
        """
        result = {}
        try:
            system_url = self._find_system_resource()
            bmc_type = 'TSM' if 'Self' in system_url else 'XCC'
            
            if bmc_type == 'XCC':
                result = self._get_url(system_url)
                if result['ret'] == False: 
                    return result
                # for current products
                oem = result['entries']['Oem']
                if 'Lenovo' in oem and 'BootSettings' in oem['Lenovo']:
                    boot_settings_url = oem['Lenovo']['BootSettings']['@odata.id']
                    result = self._get_collection(boot_settings_url)
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
                result = self._get_url(system_url + '/Bios')
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
                result = self._get_url(bios_settings_url)
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

    def get_cpu_inventory(self):
        """Get cpu inventory
        :returns: returns List of all cpu inventory when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self._find_system_resource()
            
            # Get the Processors collection
            result = self._get_collection(system_url + '/Processors')
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

    def get_memory_inventory(self, id=None):
        """Get cpu inventory
        :params id: Memory member id
        :type id: None or String of id
        :returns: returns List of all memory inventory when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self._find_system_resource()

            # Get the Processors collection
            list_memory_info = []
            result = self._get_collection(system_url + '/Memory')
            if result['ret'] == False:
                return result
            
            if id == None:
                for member in result['entries']:
                    if member["Status"]["State"] != 'Absent':
                        list_memory_info.append(member)
            else:
                for member in result['entries']:
                    if id == member['Id']:
                        list_memory_info.append(member)
                        break
                if len(list_memory_info) == 0:
                    return {'ret': False, 'msg': "Failed to find the memory with id %s. \
                              Please check if the id is correct." % id}

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
            system_url = self._find_system_resource()

            # Get the Processors collection
            result = self._get_collection(system_url + '/EthernetInterfaces')
            
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
        """Get system storage resource which are attached with storage controller.
        :returns: returns List of all system Storage when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self._find_system_resource()

            # Get the Processors collection
            result = self._get_collection(system_url + '/Storage')
            if result['ret'] == False:
                return result
            
            list_storage_info = []
            for member in result['entries']:
                storage_info = propertyFilter(member)

                if 'Drives' in member:
                    list_drives = []
                    for drive in member['Drives']:
                        result_drive = self._get_url(drive['@odata.id'])
                        if result_drive['ret'] == True:
                            drive_info = propertyFilter(result_drive['entries'])
                            list_drives.append(drive_info)
                        else:
                            return result_drive
                    storage_info['Drives'] = list_drives

                if 'Volumes' in member:
                    result_volumes = self._get_collection(member['Volumes']['@odata.id'])
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
        """Get system's SimpleStorage resource which are attached to system directly.
        :returns: returns List of all system SimpleStorage when succeeded or error message when failed
        """
        result = {}
        try:
            # Find ComputerSystem resource's url
            system_url = self._find_system_resource()

            # Get the Processors collection
            result = self._get_collection(system_url + '/SimpleStorage')
            
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
            manager_url = self._find_system_resource()
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
            system_url = self._find_system_resource()
            result = self._get_url(system_url)
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
            system_url = self._find_system_resource()
            
            # Get the system information
            system_info = {}
            result_system = self._get_url(system_url)
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

    def get_system_log(self, type='system'):
        """Get system event logs
        :params type: 'system', 'manager' or 'chassis'
        :type type: string
        :returns: returns List of system event logs
        """
        result = {}
        try:
            if type not in ['system', 'manager', 'chassis']:
                result = {'ret': False, 'msg': "Please specify type in ['system', 'manager', 'chassis']."}
                return result

            if type == "system":
                resource_url = self._find_system_resource()
            elif type == "manager":
                resource_url = self._find_manager_resource()
            else:
                resource_url = self._find_chassis_resource()
            log_service_url = resource_url + '/LogServices'
            result = self._get_url(resource_url)
            if result['ret'] == False:
                return result

            log_service_url = result['entries']['LogServices']['@odata.id']
            result = self._get_collection(log_service_url)
            if result['ret'] == False:
                return result
            
            log_details = []
            for member in result['entries']:
                id = member['Id']
                entries_url = member['Entries']['@odata.id']
                result_logs = self._get_collection(entries_url)
                if result_logs['ret'] == False:
                    return result_logs
                data_filtered = propertyFilter(result_logs['entries'])
                log = {'Id': id, 'Entries': data_filtered}
                log_details.append(log)
            result = {'ret': True, 'entries': log_details}
            return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get system storage inventory. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_system_reset_types(self):
        """Get system's reset types
        :returns: returns Dict of system reset types when succeeded or error message when failed
        """
        result = {}
        try:
            system_url = self._find_system_resource()
            result = self._get_url(system_url)
            if result['ret'] == False:
                return result
            if '@Redfish.ActionInfo' not in result['entries']["Actions"]["#ComputerSystem.Reset"]:
                return {'ret': False, 'msg': "Failed to get system reset types."}
            actioninfo_url = result['entries']['Actions']['#ComputerSystem.Reset']['@Redfish.ActionInfo']
            result = self._get_url(actioninfo_url)
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

    #############################################
    # functions for setting information.
    #############################################

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
            system_url = self._find_system_resource()
            result = self._get_url(system_url + '/Bios')
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

    def set_system_boot_order(self, bootorder):
        """Set system boot order.
        :params bootorder: Specify the bios boot order list, like: ["ubuntu", "CD/DVD Rom", "Hard Disk", "USB Storage"]
        :type bootorder: list
        :returns: returns the result to set system boot order result
        """
        result = {}
        try:
            system_url = self._find_system_resource()
            bmc_type = 'TSM' if 'Self' in system_url else 'XCC'
            
            result = self._get_url(system_url)
            if result['ret'] == False: 
                return result

            if bmc_type == 'XCC':
                # for current products
                oem = result['entries']['Oem']
                if 'Lenovo' in oem and 'BootSettings' in oem['Lenovo']:
                    boot_settings_url = oem['Lenovo']['BootSettings']['@odata.id']
                    result = self._get_collection(boot_settings_url)
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

    def set_system_power_state(self, reset_type):
        """Set system's power state, like on/off, restart.
        :params reset_type: reset system type, for example: 'On', 'GracefulShutdown', 'ForceRestart'.
        :type reset_type: string
        :returns: returns the result to set system power state. 
        """
        result = {}
        try:
            system_url = self._find_system_resource()
            result = self._get_url(system_url)
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


cmd_list = {
        "get_all_bios_attributes": {
                'help': "Get all attributes of bios", 
                'args': [{'argname': "--type", 'type': str, 'nargs': "?", 'required': False, 'help': "'current' or 'pending', default is 'current'"}]
        },
        "get_bios_attribute": {
                'help': "Get attibute value of one bios's attribute",
                'args': [{'argname': "--attribute_name", 'type': str, 'nargs': "?", 'required': True, 'help': "Attribute name of bios"}]
        },
        "get_bios_attribute_metadata": {
                'help': "Get the registry info of bios attributes",
                'args': []
        },
        "get_bios_attribute_available_value": {
                'help': "Get available value of bios attirbute",
                'args': [{'argname': "--attribute_name", 'type': str, 'nargs': "?", 'required': False, 'help': "Attribute name of bios, default is 'all'"}]
        },
        "get_bios_bootmode": {
                'help': "Get bios's boot mode",
                'args': []
        },
        "get_system_boot_order": {
                'help': "Get system's boot order",
                'args': []
        },
        "get_cpu_inventory": {
                'help': "Get system's avaliable cpu inventory",
                'args': []
        },
        "get_memory_inventory": {
                'help': "Get system's avaliable memory inventory",
                'args': [{'argname': "--id", 'type': str, 'nargs': "?", 'required': False, 'help': "Memory id, default is none"}]
        },
        "get_system_ethernet_interfaces": {
                'help': "Get system's ethernet interfaces",
                'args': []
        },
        "get_system_storage": {
                'help': "Get system's storage, which are attached with storage controller",
                'args': []
        },
        "get_system_simple_storage": {
                'help': "Get system's simple storage, which are attached with system directly",
                'args': []
        },
        "get_storage_inventory": {
                'help': "Get all storages' inventory",
                'args': []
        },
        "get_system_power_state": {
                'help': "Get system's power state",
                'args': []
        },
        "get_system_inventory": {
                'help': "Get system's inventory",
                'args': []
        },
        "get_system_log": {
                'help': "Get event logs of system, manager or chassis",
                'args': [{'argname': "--type", 'type': str, 'nargs': "?", 'required': False, 'help': "Log of 'system','manager' or 'chassis', default is 'system'"}]
        },       
        "get_system_reset_types": {
                'help': "Get system's available reset actions.",
                'args': []
        },
        "set_bios_attribute": {
                'help': "Set one attribute of bios",
                'args': [{'argname': "--attribute_name", 'type': str, 'nargs': "?", 'required': True, 'help': "Attribute name of bios"},
                         {'argname': "--attribute_value", 'type': str, 'nargs': "?", 'required': True, 'help': "New value of this attribute"}]
        },
        "set_system_boot_order": {
                'help': "Set system's boot order",
                'args': [{'argname': "--bootorder", 'type': str, 'nargs': "*", 'required': True, 'help': "Bios boot order list, like: 'CD/DVD Rom' 'Hard Disk'"}]
        },
        "set_bios_bootmode": {
                'help': "Set system's boot mode",
                'args': [{'argname': "--bootmode", 'type': str, 'nargs': "?", 'required': True, 'help': "System's boot mode. please use 'get_bios_bootmode' to list available boot mode."}]
        },
        "set_system_power_state": {
                'help': "Set system's power state",
                'args': [{'argname': "--reset_type", 'type': str, 'nargs': "?", 'required': True, 'help': "Reset action, like 'GraceRestart', 'ForceRestart'. please use 'get_system_reset_types' to get available reset types."}]
        }
}

def add_sub_parameter(subcommand_parsers):
    for func in cmd_list.keys():
        parser_function = subcommand_parsers.add_parser(func, help=cmd_list[func]['help'])
        for arg in cmd_list[func]['args']:
            parser_function.add_argument(arg['argname'], type=arg['type'], nargs=arg['nargs'], required=arg['required'], help=arg['help'])

def run_subcommand(args):
    """ return result of running subcommand """

    parameter_info = {}
    parameter_info = parse_common_parameter(args)

    cmd = args.subcommand_name
    if cmd not in cmd_list.keys():
        result = {'ret': False, 'msg': "Subcommand is not correct."}
        usage()
        return result

    try:
        client = SystemClient(ip=parameter_info['ip'], 
                                    username=parameter_info['user'], 
                                    password=parameter_info['password'], 
                                    configfile=parameter_info['config'], 
                                    auth=parameter_info['auth'])
        client.login()
    except Exception as e:
        LOGGER.debug("%s" % traceback.format_exc())
        msg = "Failed to login. Error message: %s" % (repr(e))
        LOGGER.error(msg)
        LOGGER.debug(parameter_info)
        return {'ret': False, 'msg': msg}

    result = {}
    if cmd == 'get_all_bios_attributes':
        parameter_info["type"] = 'current'
        if args.type:
            parameter_info["type"] = args.type
        result = client.get_all_bios_attributes(parameter_info["type"])

    elif cmd == 'get_bios_attribute':
        parameter_info["attribute_name"] = args.attribute_name
        result = client.get_bios_attribute(parameter_info["attribute_name"])

    elif cmd == 'get_bios_attribute_metadata':
        result = client.get_bios_attribute_metadata()

    elif cmd == 'get_bios_attribute_available_value':
        parameter_info["attribute_name"] = 'all'
        if args.attribute_name:
            parameter_info["attribute_name"] = args.attribute_name
        result = client.get_bios_attribute_available_value(parameter_info["attribute_name"])

    elif cmd == 'get_bios_bootmode':
        result = client.get_bios_bootmode()

    elif cmd == 'get_system_boot_order':
        result = client.get_system_boot_order()

    elif cmd == 'get_cpu_inventory':
        result = client.get_cpu_inventory()

    elif cmd == 'get_memory_inventory':
        parameter_info["id"] = args.id
        result = client.get_memory_inventory(parameter_info["id"])

    elif cmd == 'get_system_ethernet_interfaces':
        result = client.get_system_ethernet_interfaces()

    elif cmd == 'get_system_storage':
        result = client.get_system_storage()

    elif cmd == 'get_system_simple_storage':
        result = client.get_system_simple_storage()

    elif cmd == 'get_storage_inventory':
        result = client.get_storage_inventory()

    elif cmd == 'get_system_power_state':
        result = client.get_system_power_state()

    elif cmd == 'get_system_inventory':
        result = client.get_system_inventory()

    elif cmd == 'get_system_log':
        parameter_info["type"] = 'system'
        if args.type:
            parameter_info["type"] = args.type
        result = client.get_system_log(parameter_info["type"])

    elif cmd == 'get_system_reset_types':
        result = client.get_system_reset_types()

    elif cmd == 'set_bios_attribute':
        parameter_info["attribute_name"] = args.attribute_name
        parameter_info["attribute_value"] = args.attribute_value
        result = client.set_bios_attribute(parameter_info["attribute_name"], parameter_info["attribute_value"])

    elif cmd == 'set_system_boot_order':
        parameter_info["bootorder"] = args.bootorder
        result = client.set_system_boot_order(parameter_info["bootorder"])

    elif cmd == 'set_bios_bootmode':
        parameter_info["bootmode"] = args.bootmode
        result = client.set_bios_bootmode(parameter_info["bootmode"])

    elif cmd == 'set_system_power_state':
        parameter_info["reset_type"] = args.reset_type
        result = client.set_system_power_state(parameter_info["reset_type"])

    else:
        result = {'ret': False, 'msg': "Subcommand is not supported."}

    client.logout()
    return result


def usage():
    print("  System subcommands:")
    for cmd in cmd_list.keys():
        print("    %-42s Help:  %-120s" % (cmd, cmd_list[cmd]['help']))
        for arg in cmd_list[cmd]['args']:
            print("                %-30s Help:  %-120s" % (arg['argname'], arg['help']))
    print('')

def main(argv):
    """Lenovo system client's main"""

    argget = argparse.ArgumentParser(description="Lenovo Redfish Tool - System Client")
    add_common_parameter(argget)

    subcommand_parsers = argget.add_subparsers(dest='subcommand_name', help='all subcommands')
    add_sub_parameter(subcommand_parsers)

    # Parse the parameters
    args = argget.parse_args()
    result = run_subcommand(args)
    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))


if __name__ == "__main__":

    main(sys.argv)