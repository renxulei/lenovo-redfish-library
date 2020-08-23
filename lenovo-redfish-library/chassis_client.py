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
import logging
import json
import traceback 

from .redfish_base import RedfishBase
from .utils import *
from .utils import add_common_parameter
from .utils import parse_common_parameter

class ChassisClient(RedfishBase):
    """A client for accessing lenovo system resource"""

    def __init__(self, ip='', username='', password='',
                 configfile='config.ini', auth=''):
        """Initialize ChassisClient"""

        super(ChassisClient, self).__init__(
            ip=ip, username=username, password=password, 
            configfile=configfile, auth=auth
        )

    #############################################
    # functions for getting information.
    #############################################

    def get_pci_inventory(self):
        """Get PCI devices inventory
        :returns: returns List of all PCI devices when succeeded or error message when failed
        """
        result = {}
        try:
            list_pci_info = []
            chassis_url = self._find_chassis_resource()
            result_pci = self._get_collection(chassis_url + '/PCIeDevices')
            if result_pci['ret'] == False:
                # Try to find PCIeDevices under ComputerSystem.
                system_url = self._find_system_resource()
                result = self._get_url(system_url)
                if result['ret'] == False:
                    return result
                if 'PCIeDevices' not in result['entries'].keys():
                    return {'ret': False, 'msg': "Failed to find 'PCIeDevices' in ComputerSystem."}
                for member in result['entries']['PCIeDevices']:
                    result = self._get_url(member['@odata.id'])
                    if result['ret'] == False:
                        return result
                    data_filtered = propertyFilter(result['entries'])
                    list_pci_info.append(data_filtered)
            else:
                list_pci_info = propertyFilter(result_pci['entries'])

            for member in list_pci_info:
                if 'PCIeFunctions' in member:
                    result_pci_func = self._get_collection(member['PCIeFunctions']['@odata.id'])
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
            chassis_url = self._find_chassis_resource()
            
            list_nic_info = []
            result_nic = self._get_collection(chassis_url + '/NetworkAdapters')
            
            if result_nic['ret'] == True:
                list_nic_info = propertyFilter(result_nic['entries'], common_property_excluded, ['@Redfish'])
                for member in list_nic_info:
                    if 'NetworkDeviceFunctions' in member:
                        result_nic_func = self._get_collection(member['NetworkDeviceFunctions']['@odata.id'])
                        if result_nic_func['ret'] == False:
                            return result_nic_func
                        data_filtered = propertyFilter(result_nic_func['entries'], common_property_excluded)
                        member['NetworkDeviceFunctions'] = data_filtered
                    if 'NetworkPorts' in member:
                        result_nic_ports = self._get_collection(member['NetworkPorts']['@odata.id'])
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
            chassis_url = self._find_chassis_resource()        
            result = self._get_url(chassis_url + '/Thermal')
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
            chassis_url = self._find_chassis_resource()        
            result = self._get_url(chassis_url + '/Thermal')
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

    def _get_power_info(self, property=None):
        """Get property info from chassis power info 
        :returns: returns List of property info of power when succeeded or error message when failed
        """
        try:
            chassis_url = self._find_chassis_resource()        
            result = self._get_url(chassis_url + '/Power')
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
        return self._get_power_info('PowerSupplies')

    def get_power_redundancy(self):
        """Get power redundancy info
        :returns: returns List of power redundancy info when succeeded or error message when failed
        """
        
        return self._get_power_info('Redundancy')

    def get_power_voltages(self):
        """Get power voltages info
        :returns: returns List of power voltages info when succeeded or error message when failed
        """
        
        return self._get_power_info('Voltages')

    def get_power_metrics(self):
        """Get power metrics info
        :returns: returns Dict of power metrics of whole system when succeeded or error message when failed
        """
        power_metrics = {}
        result = self._get_power_info('PowerControl')
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
        result = self._get_power_info('PowerControl')
        if result['ret'] == False:
            return result
        for member in result['entries']:
            if 'PowerLimit' in member:
                return {'ret': True, 'entries': member['PowerLimit']}
        return {'ret': False, 'msg': "No power limit exist."}

    #############################################
    # functions for setting information.
    #############################################

    # ToDo

chassis_cmd_list = {
        "get_pci_inventory": {
                'help': "Get pci devices' inventory", 
                'args': []
        },
        "get_nic_inventory": {
                'help': "Get nic devices' inventory",
                'args': []
        },
        "get_fan_inventory": {
                'help': "Get fan devices' inventory",
                'args': []
        },
        "get_temperatures_inventory": {
                'help': "Get temperature info",
                'args': []
        },
        "get_psu_inventory": {
                'help': "Get psu's inventory",
                'args': []
        },
        "get_power_redundancy": {
                'help': "Get power redundancy info",
                'args': []
        },
        "get_power_voltages": {
                'help': "Get power voltages' inventory",
                'args': []
        },
        "get_power_metrics": {
                'help': "Get power consumption's info",
                'args': []
        },
        "get_power_limit": {
                'help': "Get power limitation of whole system",
                'args': []
        }
}

def add_chassis_parameter(subcommand_parsers):
    for func in chassis_cmd_list.keys():
        parser_function = subcommand_parsers.add_parser(func, help=chassis_cmd_list[func]['help'])
        for arg in chassis_cmd_list[func]['args']:
            parser_function.add_argument(arg['argname'], type=arg['type'], nargs=arg['nargs'], required=arg['required'], help=arg['help'])

def run_chassis_subcommand(args):
    """ return result of running subcommand """

    parameter_info = {}
    parameter_info = parse_common_parameter(args)

    cmd = args.subcommand_name
    if cmd not in chassis_cmd_list.keys():
        result = {'ret': False, 'msg': "Subcommand is not correct."}
        usage()
        return result

    try:
        client = ChassisClient(
                     ip=parameter_info['ip'],
                     username=parameter_info['user'],
                     password=parameter_info['password'],
                     configfile=parameter_info['config'],
                     auth=parameter_info['auth']
                 )
        client.login()
    except Exception as e:
        LOGGER.debug("%s" % traceback.format_exc())
        msg = "Failed to login. Error message: %s" % (repr(e))
        LOGGER.error(msg)
        LOGGER.debug(parameter_info)
        return {'ret': False, 'msg': msg}

    result = {}
    if cmd == 'get_pci_inventory':
        result = client.get_pci_inventory()

    elif cmd == 'get_nic_inventory':
        result = client.get_nic_inventory()

    elif cmd == 'get_fan_inventory':
        result = client.get_fan_inventory()

    elif cmd == 'get_temperatures_inventory':
        result = client.get_temperatures_inventory()

    elif cmd == 'get_psu_inventory':
        result = client.get_psu_inventory()

    elif cmd == 'get_power_redundancy':
        result = client.get_power_redundancy()

    elif cmd == 'get_power_voltages':
        result = client.get_power_voltages()

    elif cmd == 'get_power_metrics':
        result = client.get_power_metrics()

    elif cmd == 'get_power_limit':
        result = client.get_power_limit()

    else:
        result = {'ret': False, 'msg': "Subcommand is not supported."}

    client.logout()
    return result

def chassis_usage():
    print("  Chassis subcommands:")
    for cmd in chassis_cmd_list.keys():
        print("    %-42s Help:  %-120s" % (cmd, chassis_cmd_list[cmd]['help']))
        for arg in chassis_cmd_list[cmd]['args']:
            print("                %-30s Help:  %-120s" % (arg['argname'], arg['help']))
    print('')

def main(argv):
    """Lenovo chassis client's main"""

    argget = argparse.ArgumentParser(description="Lenovo Redfish Tool - Chassis Client")
    add_common_parameter(argget)

    subcommand_parsers = argget.add_subparsers(dest='subcommand_name', help='all subcommands')
    add_chassis_parameter(subcommand_parsers)

    # Parse the parameters
    args = argget.parse_args()
    result = run_chassis_subcommand(args)
    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))


if __name__ == "__main__":

    main(sys.argv)
