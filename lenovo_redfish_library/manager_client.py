###
#
# Lenovo Redfish Library - ManagerClient Class
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
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from .redfish_base import RedfishBase
from .utils import *
from .utils import add_common_parameter
from .utils import parse_common_parameter

class ManagerClient(RedfishBase):
    """A client for managing bmc"""

    def __init__(self, ip='', username='', password='',
                 configfile='config.ini', auth=''):
        """Initialize ManagerClient"""

        super(ManagerClient, self).__init__(
            ip=ip, username=username, password=password, 
            configfile=configfile, auth=auth
        )

    #############################################
    # functions for getting information.
    #############################################

    def get_bmc_inventory(self):
        """Get bmc inventory    
        :returns: returns Dict of bmc inventory when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            
            # Get the BMC information
            bmc_info = {}
            result_manager = self._get_url(manager_url)
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
        """Get bmc network protocol which provide bmc's network services info.      
        :returns: returns Dict of bmc networkprotocol when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result_network = self._get_url(manager_url + '/NetworkProtocol')
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
        """Get bmc serial interfaces    
        :returns: returns List of bmc serial interfaces when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()          
            result_serial = self._get_collection(manager_url + '/SerialInterfaces')
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
        """Get bmc ethernet interfaces
        :returns: returns List of bmc nic when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result_ethernet = self._get_collection(manager_url + '/EthernetInterfaces')
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

    def get_bmc_hostinterfaces(self):
        """Get bmc Host Interfaces    
        :returns: returns List of bmc host interfaces when succeeded or error message when failed
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result_hostinfs = self._get_collection(manager_url + '/HostInterfaces')
            if result_hostinfs['ret'] == False:
                return result_hostinfs

            hostinf_info_list = propertyFilter(result_hostinfs['entries'])
            for member in hostinf_info_list:
                if 'HostEthernetInterfaces' in member.keys():
                    host_eth_url = member["HostEthernetInterfaces"]['@odata.id']
                    result_host_eth = self._get_collection(host_eth_url)
                    if result_host_eth['ret'] == True: 
                        member['HostEthernetInterfaces'] = propertyFilter(result_host_eth['entries'])
                    else:
                        return result_host_eth
                if 'ManagerEthernetInterface' in member.keys():
                    manager_eth_url = member["ManagerEthernetInterface"]['@odata.id']
                    result_manager_eth = self._get_url(manager_eth_url)
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
        """Get bmc ntp info    
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

    def get_event_log(self, type='manager'):
        """Get event logs
        :params type: 'system', 'manager' or 'chassis'
        :type type: string
        :returns: returns List of event logs
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
            msg = "Failed to get event logs. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def get_bmc_users(self):
        """Get bmc user accounts
        :returns: returns List of bmc user accounts.
        """
        result = {}
        try:
            result = self._get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account_info_list = []
            for member in result['entries']:
                if "Links" in member and "Role" in member["Links"]:
                    accounts_role_url = member["Links"]["Role"]["@odata.id"]
                    # Get the BMC user privileges info
                    result_role = self._get_url(accounts_role_url)
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

    def get_bmc_virtual_media(self):
        """Get virtual media of bmc
        :returns: returns List of virtual media.
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result = self._get_collection(manager_url + '/VirtualMedia')
            if result['ret'] == False:
                return result

            virtual_media_list = propertyFilter(result['entries'])
            return {'ret': True, 'entries': virtual_media_list}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to get virtual media of bmc. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    #############################################
    # functions for setting information.
    #############################################

    def _check_bmc_type(self):
        manager_url = self._find_manager_resource()
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
            bmc_type = self._check_bmc_type()
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
            result = self._get_collection('/redfish/v1/AccountService/Accounts')
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
                #result_role = self._get_url(roleuri)
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
            bmc_type = self._check_bmc_type()
            result = self._get_collection('/redfish/v1/AccountService/Accounts')
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
        :params enabled: disable(0) or enable(1) bmc service
        :type enabled: int
        :params port: network service's port
        :type port: int
        :returns: returns the result to set bmc's network service
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result = self._get_url(manager_url + '/NetworkProtocol')
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
                    return {'ret': False, 'msg': "Please specify 'enabled' parameter."}
                body = {service:{"ProtocolEnabled": bool(int(enabled))}}
            elif service in ["SSH", "SNMP"]:
                parameter_info = {}
                if enabled == None and port == None: 
                    return {'ret': False, 'msg': "Please specify 'enabled' or 'port' parameter."}
                if enabled != None:
                    parameter_info['ProtocolEnabled'] = bool(int(enabled))
                if port != None:
                    parameter_info['Port'] = int(port)
                body = {service: parameter_info}
            elif service in ["HTTPS", "VirtualMedia"]:
                if port == None:
                    return {'ret': False, 'msg': "Please specify port parameter."}
                body = {service:{"Port": int(port)}}
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

    def lenovo_export_ffdc(self, data_type=None, fsprotocol=None, fsip=None, fsport=None, fsdir=None, fsusername=None, fspassword=None):
        """Export FFDC info.
        :params data_type: only for XCC. Data collection type: ProcessorDump, ServiceDataFile or BootPOSTDump.
        :type data_type: string
        :params fsprotocol: transfer protocol. For XCC: SFTP/TFTP/None(local save). Fox TSM: HTTP only.
        :type fsprotocol: string
        :params fsip: file server ip, like sftp or tftp server ip
        :type fsip: string
        :params fsport: file server port, only for HTTP. Default is '8080'
        :type fsport: Number
        :params fsusername: username to access sftp file server 
        :type fsusername: string
        :params fspassword: password to access sftp file server
        :type fspassword: string
        :params fsdir: full path of dir on file server(sftp/tftp) under which ffdc file will be saved. \
                       for http file server, fsdir should be the path to HTTP service root. 
                       example: http://10.103.62.175:8080/upload, the fsdir should be '/upload'
        :type fsdir: string
        :returns: returns the result of exporting ffdc
        """
        result = {}
        # Check parameter
        if fsprotocol and (fsip is None or fsip == '' or fsprotocol.upper() not in ['SFTP', 'TFTP', 'HTTP']):
            result = {'ret': False, 'msg': "please check if protocol and file server info are correct."}
            return result
        try:
            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_url(manager_url)
            if result['ret'] == False:
                return result

            dict_bmc = result['entries']
            export_uri = ""
            local_download = False
            if bmc_type == 'XCC':
                servicedata_uri = None
                if 'Oem' in dict_bmc and 'Lenovo' in dict_bmc['Oem'] and 'ServiceData' in dict_bmc['Oem']['Lenovo']:
                    # Get servicedata uri via manager uri response resource
                    servicedata_uri = dict_bmc['Oem']['Lenovo']['ServiceData']['@odata.id']
                else:
                    result = {'ret': False, 'msg': "Failed to find servicedata uri."}
                    return result
                # Get servicedata resource
                result = self._get_url(servicedata_uri)
                if result['ret'] == False:
                    return result

                # Get export ffdc data uri via servicedaata uri response resource
                ffdc_data_uri = result['entries']['Actions']['#LenovoServiceData.ExportFFDCData']['target']

                # Build post request body and Get the user specified parameter
                body = {}
                body['InitializationNeeded'] = True
                if data_type == None or data_type == '':
                    data_type = "ProcessorDump"
                body['DataCollectionType'] = data_type

                # Check the transport protocol, only support sftp and tftp protocols
                if fsprotocol:
                    export_uri = fsprotocol.lower() + "://" + fsip + ":" + fsdir + "/"
                    body['ExportURI'] = export_uri

                    # Get the user specified sftp username and password when the protocol is sftp
                    if fsprotocol.upper() == "SFTP":
                        if not fsusername or not fspassword:
                            msg = "you must specify username and password for accessing sftp server."
                            result = {"ret": False, "msg": msg}
                            return result
                        else:
                            body['Username'] = fsusername
                            body['Password'] = fspassword
                else:
                    local_download = True
            if bmc_type == 'TSM':
                if 'Actions' in dict_bmc and 'Oem' in dict_bmc['Actions'] and \
                   '#Manager.DownloadServiceData' in dict_bmc['Actions']['Oem']:
                    if fsprotocol == None or fsprotocol.upper() != "HTTP":
                        msg = "Target Server only supports HTTP protocol, please specify HTTP file server to download server data."
                        result = {"ret": False, "msg": msg}
                        return result
                    body = {}
                    body['serverIP'] = fsip
                    if fsport == None or fsport == '':
                        fsport = "8080"
                    body['serverPort'] = fsport
                    body['folderPath'] = fsdir
                    export_uri = fsprotocol.lower() + "://" + fsip + ":" + str(fsport) + fsdir + "/"
                    ffdc_data_uri = result['entries']['Actions']['Oem']['#Manager.DownloadServiceData']['target']

            time_start=time.time()
            response = self.post(ffdc_data_uri, body=body)
            if response.status not in [202]:
                result = {'ret': False, 'msg': "Failed to export ffdc. Error code is %s. Error message is %s. " % \
                          (response_code, response.text)}
                LOGGER.error(result['msg'])
                return result
            task_uri = response.dict['@odata.id']
            # Check collect result via returned task uri
            print("Start downloading ffdc files and may take 3~10 minutes...")
            while True:
                response = self.get(task_uri, None)
                if response.status not in [200, 202]:
                    result = {'ret': False, 'msg': "Failed to get task: '%s'. Error code is %s. Error message is %s. " % \
                              (task_uri, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result

                time_end = time.time()
                task_state = response.dict['TaskState']
                if task_state == "Completed":
                    # If the user does not specify export uri, the ffdc data file will be downloaded to the local
                    if local_download == True:
                        # Download FFDC data from download uri when the task completed
                        download_uri = response.dict['Oem']['Lenovo']['FFDCForDownloading']['Path']
                        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                        headers = {}
                        headers['Content-Type'] = "application/json"
                        # We must use session connection to get ffdc file.
                        if self._auth == 'basic':
                            self.login(auth='session')
                        headers["X-Auth-Token"] = self.get_session_key()

                        download_uri = "https://" + self._ip + download_uri
                        response_download = requests.get(download_uri, headers=headers, verify=False)
                        
                        if response_download.status_code not in [200, 202]:
                            result = {'ret': False, 'msg': "Failed to get ffdc data: '%s'. Error code is %s. Error message is %s. " % \
                                      (download_uri, response_download.status_code, response_download.text)}
                            LOGGER.error(result['msg'])
                            return result
                            
                        ffdc_file_name = download_uri.split('/')[-1]
                        ffdc_fullpath = os.getcwd() + os.sep + ffdc_file_name
                        with open(ffdc_fullpath, 'wb') as f:
                            f.write(response_download.content)

                        time_end = time.time()
                        print('time cost: %.2f' %(time_end-time_start)+'s')
                        self.delete(task_uri, None)
                        result = {'ret': True, 'msg':  "Succeed to export The FFDC data into file: '%s'." % ffdc_fullpath, 'entries': response.dict}
                        return result
                    else:
                        time_end = time.time()
                        print('time cost: %.2f' %(time_end-time_start)+'s')
                        result = {'ret': True, 'msg':  "The FFDC data is saved in %s " % export_uri}
                        return result
                elif task_state in ["Exception", "Killed"]:
                    self.delete(task_uri, None)
                    result = {"ret": False, "msg": "Failed to download FFDC data, task state is '%s'." % task_state, 'entries': response.dict}
                    return result
                else: # task not in end state
                    # Wait max 10 minutes to avoid endless loop.
                    time_now = time.time()
                    if time_now - time_start > 600:
                        result = {'ret': False, 'msg':  "It is over 10 minutes to export FFDC data.", 'entries': response.dict}
                        return result
                    time.sleep(10)
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to export ffdc. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_mount_virtual_media(self, image, fsprotocol, fsip, fsdir, fsport=None, inserted=1, write_protected=1):
        """Mount virtual media into system
        :params image: image's file name
        :type image: string
        :params fsprotocol: transfer protocol, XCC: [HTTP, NFS]. TSM: [NFS]
        :type fsprotocol: string
        :params fsip: file server's ip, like nfs or http file server
        :type fsip: string
        :params fsdir: path to image file on file server 
        :type fsdir: string
        :params fsport: port of file server 
        :type fsport: int
        :params inserted: 1 or 0. 1: True, 0: False
        :type inserted: int
        :params write_protected: 1 or 0. 1: True, 0: False
        :type write_protected: int
        :returns: returns the result of mounting virtual media
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_collection(manager_url + '/VirtualMedia')
            if result['ret'] == False:
                return result

            if bmc_type == 'XCC':
                protocol_scope = ['NFS', 'HTTP']
                if fsprotocol == None or fsprotocol.upper() not in protocol_scope:
                    result = {'ret': False, 'msg': "Please specify correct protocol. available protocol is '%s'." % protocol_scope}
                    return result
                
                target_vm = None
                for member in result['entries']:
                    if member['Id'].startswith("EXT") and (member['ImageName'] == None or member['ImageName'] == ''):
                        target_vm = member
                        break
                    continue
                
                if target_vm == None:
                    result = {'ret': False, 'msg': "There are no avaliable virtual media."}
                    return result

                # Via patch request mount virtual media
                if fsport == None:
                    fsport = ''
                else:
                    fsport = '%s' % fsport
                fsdir = "/" + fsdir.strip("/")
                protocol = fsprotocol.lower()
                
                if protocol == 'samba':
                    protocol = 'smb'
                if protocol == 'nfs':
                    image_uri = fsip + ":" + fsport + fsdir + "/" + image
                else:
                    image_uri = protocol + "://" + fsip + ":" + fsport + fsdir + "/" + image
                body = {"Image": image_uri, "WriteProtected": bool(int(write_protected)),
                        "Inserted": bool(int(inserted))}
                response = self.patch(target_vm["@odata.id"], body=body)

            if bmc_type == 'TSM':
                protocol_scope = ['NFS']
                if fsprotocol == None or fsprotocol.upper() not in protocol_scope:
                    result = {'ret': False, 'msg': "Please specify correct protocol. available protocol is '%s'." % protocol_scope}
                    return result
                if not image.endswith(".iso") and not image.endswith(".nrg"):
                    result = {'ret': False, 'msg': "Only support CD/DVD media file type: (*.iso), (*.nrg)."}
                    return result
                target_vm = None
                for member in result['entries']:
                    if member['ImageName'] == None or member['ImageName'] == '':
                        target_vm = member
                        break
                    continue
                
                if target_vm == None:
                    result = {'ret': False, 'msg': "There are no avaliable virtual media."}
                    return result

                # Via post action to mount virtual media
                fsdir = "/" + fsdir.strip("/")
                image_uri = fsprotocol.lower() + "://" + fsip + fsdir + "/" + image
                insert_media_url = target_vm["Actions"]["#VirtualMedia.InsertMedia"]["target"]
                body = {"Image": image_uri, "TransferProtocolType": fsprotocol.upper()}
                response = self.post(insert_media_url, body=body)
                
            if response.status in [200, 202, 204]:
                result = {'ret': True, 'msg': "Succeed to mount the image: %s." % image}
                return result
            else:
                result = {'ret': False, 'msg': "Failed to mount the image '%s'. Error code is %s. Error message is %s. " % \
                          (image_uri, response.status, response.text)}
                LOGGER.error(result['msg'])
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to mount virtual media. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_umount_virtual_media(self, image):
        """Unmount virtual media from system.
        :params image: image name. virtual media with image name will be ejected
        :type image: string
        :returns: returns the result of unmounting virtual media
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_collection(manager_url + '/VirtualMedia')
            if result['ret'] == False:
                return result

            target_vm = None
            for member in result['entries']:
                if member['ImageName'] == image:
                    target_vm = member
                    break
                continue
            if target_vm == None:
                result = {'ret': False, 'msg': "There is no virtual media with name: '%s'." % image}
                return result

            if bmc_type == 'XCC':
                body = {"Image": None}
                response = self.patch(target_vm["@odata.id"], body=body)
                if response.status in [200,204]:
                    result = {'ret': True, 'msg': "Succeed to unmount image '%s'." % image}
                    return result
                else:
                    result = {'ret': False, 'msg': "Failed to unmount the image '%s'. Error code is %s. Error message is %s. " % \
                              (image, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result

            if bmc_type == 'TSM':
                eject_media_url = target_vm["Actions"]["#VirtualMedia.EjectMedia"]["target"]
                body = {}
                response = self.post(eject_media_url, body=body)
                if response.status == 204:
                    result = {'ret': True, 'msg': "Succeed to unmount image '%s'." % image}
                    return result
                else:
                    result = {'ret': False, 'msg': "Failed to unmount the image '%s'. Error code is %s. Error message is %s. " % \
                              (image, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to unmount virtual media. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_bmc_config_backup(self, backup_password, backup_file=None, httpip=None, httpport=None, httpdir=None):
        """Backup bmc configuration
        :params backup_password: backup password for encrypting configuration file
        :type backup_password: string
        :params backup_file: backup file of configuration, only for XCC. \
            Default is 'bmc_config_backup.json' under current working directory
        :type backup_file: string
        :params httpip: http file server's ip, only for TSM
        :type httpip: string
        :params httpport: http file server's port, only for TSM
        :type httpport: number
        :params httpdir: folder on file server to save the backup file, only for TSM
        :type httpdir: string
        :returns: returns the result of backuping bmc configuration
        """
        result = {}
        try:
            if len(backup_password) < 9:
                result = {'ret': False, 'msg': "Password is at least 9 characters"}
                return result

            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_url(manager_url)
            if result['ret'] == False:
                return result

            if bmc_type == 'XCC':
                if backup_file == None:
                    backup_file = os.getcwd() + os.sep + 'bmc_config_backup.json'
                config_url = result['entries']['Oem']['Lenovo']['Configuration']['@odata.id']
                result = self._get_url(config_url)
                if result['ret'] == False:
                    return result

                # Backup configuration
                backup_target_url = result['entries']['Actions']['#LenovoConfigurationService.BackupConfiguration']['target']
                backup_body = {"Passphrase": backup_password}
                response = self.post(backup_target_url, body=backup_body)
                if response.status in [200]:
                    #with open(filename, 'w') as f:
                    #    json.dump(result['entries'], f, indent=2)
                    f_back_file = open(backup_file,'w+')
                    json.dump(response.dict["data"], f_back_file, separators=(',', ':'))
                    f_back_file.close()
                    size = os.path.getsize(backup_file)
                    size = size/1024
                    if(size <= 255):
                        result = {'ret': True, 'msg': "Succeed to back up bmc configuration, backup file is: %s." % backup_file}
                    else:
                        os.remove(backup_file)
                        result = {'ret': False,'msg': "Failed to back up bmc configuration, configuration data is over 255KB."}
                    return result
                else:
                    result = {'ret': False, 'msg': "Failed to back up bmc configuration. Error code is %s. Error message is %s. " % \
                              (response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result

            if bmc_type == 'TSM':
                if httpip is None or httpdir is None:
                    msg = "This product only supports HTTP protocol, please specify httpip and httpdir."
                    result = {"ret": False, "msg": msg}
                    return result
                backup_target_url = result['entries']['Actions']['Oem']['#Manager.Backup']['target']
                body = {}
                body['BackupType'] = 'SNMP, KVM, NetworkAndServices, IPMI, NTP, Authentication, SYSLOG'
                body['password'] = backup_password
                body['serverIP'] = httpip
                body['serverPort'] = int(httpport)
                body['folderPath'] = httpdir.strip("/")
                export_uri = 'http://' + httpip + ':' + str(httpport) + '/' + httpdir
                
                print("Start backing up bmc configuration, may take 1~5 minutes ...")
                response = self.post(backup_target_url, body=body)
                if response.status not in [202]:
                    result = {'ret': False, 'msg': "Failed to back up bmc configuration. Url: %s. Error code is %s. Error message is %s. " % \
                              (backup_target_url, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result

                task_uri = response.dict['@odata.id']
                result = self._task_monitor(task_uri)
                self.delete(task_uri, None)
                if result['ret'] == True:
                    result['msg'] = "Succeed to back up bmc configuration, file is saved in '%s'." % export_uri
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to back up bmc configuration. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_bmc_config_restore(self, backup_password, backup_file=None, httpip=None, httpport=None, httpdir=None):
        """Restore bmc configuration
        :params backup_password: backup password for decrypting configuration file
        :type backup_password: string
        :params backup_file: backup file of configuration, only for XCC. \
            Default is 'bmc_config_backup.json' under current working directory
        :type backup_file: string
        :params httpip: http file server's ip, only for TSM
        :type httpip: string
        :params httpport: http file server's port, only for TSM
        :type httpport: number
        :params httpdir: folder on file server, under which file restored is saved, only for TSM
        :type httpdir: string
        :returns: returns the result of restoring bmc configuration
        """
        result = {}
        try:
            if len(backup_password) < 9:
                result = {'ret': False, 'msg': "Password is at least 9 characters"}
                return result

            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_url(manager_url)
            if result['ret'] == False:
                return result

            if bmc_type == 'XCC':
                if backup_file == None:
                    backup_file = os.getcwd() + os.sep + 'bmc_config_backup.json'
                config_url = result['entries']['Oem']['Lenovo']['Configuration']['@odata.id']
                result = self._get_url(config_url)
                if result['ret'] == False:
                    return result

                # load configuration file
                f_back_file = open(backup_file,'r')
                try:
                    list_data = json.load(f_back_file)
                except:
                    result = {'ret': False, 'msg': "load file error,Please check your input file"}
                    return result
                if len(list_data) == 0:
                    result = {'ret': False, 'msg': "File content is empty."}
                    return result

                restore_body = {}
                restore_body = {"ConfigContent": list_data, "Passphrase": backup_password}
                restore_target_url = result['entries']['Actions']['#LenovoConfigurationService.RestoreConfiguration']['target']
                print("Start restoring bmc configuration, may take 1~5 minutes ...")
                response = self.post(restore_target_url, body=restore_body)
                
                if response.status not in [200]:
                    result = {'ret': False, 'msg': "Failed to restore bmc configuration. Url: %s. Error code is %s. Error message is %s. " % \
                              (restore_target_url, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result

                # Check restore status after action
                for i in range(120): # Wait max 10 minutes
                    result = self._get_url(config_url)
                    if result['ret'] == False:
                        return result
                    if 'RestoreStatus' in result['entries'] and 'Restore was successful' in result['entries']['RestoreStatus']:
                        result = {'ret': True, 'msg':"Succeed to restore bmc configuration."}
                        return result
                    time.sleep(5)

                result = {'ret': False, 'msg':"Restoring bmc configuration does not finished in 10 minutes."}
                return result

            if bmc_type == 'TSM':
                if httpip is None or httpdir is None or backup_file is None:
                    msg = "This product only supports HTTP protocol, please specify httpip, httpdir and backup_file."
                    result = {"ret": False, "msg": msg}
                    return result
                body = {}
                body['RestoreFileName'] = backup_file
                body['password'] = backup_password
                body['serverIP'] = httpip
                body['serverPort'] = int(httpport)
                body['folderPath'] = httpdir.strip("/")
                export_uri = 'http://' + httpip + ':' + str(httpport) + '/' + httpdir

                restore_url = result['entries']['Actions']['Oem']['#Manager.Restore']['target']              
                print("Start restoring bmc configuration, may take 1~5 minutes ...")
                response = self.post(restore_url, body=body)
                if response.status not in [202]:
                    result = {'ret': False, 'msg': "Failed to restore bmc configuration. Url: %s. Error code is %s. Error message is %s. " % \
                              (restore_url, response.status, response.text)}
                    LOGGER.error(result['msg'])
                    return result
                task_uri = response.dict['@odata.id']
                result = self._task_monitor(task_uri)
                self.delete(task_uri, None)
                if result['ret'] == True:
                    result['msg'] = "Succeed to restore bmc configuration. BMC will restart to reload the configuration, may take 1~5 minutes ..."
                return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to restore bmc configuration. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def reset_bmc(self, reset_type=None):
        """Reset bmc
        :params reset_type: for XCC: ['GracefulRestart', 'ForceRestart']. for TSM: ['ForceRestart']
        :type reset_type: string
        :returns: returns the result of reseting bmc
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_url(manager_url)
            if result['ret'] == False:
                return result

            reset_scope = ['GracefulRestart', 'ForceRestart'] if bmc_type == 'XCC' else ['ForceRestart']
            if reset_type != None and reset_type not in reset_scope:
                result = {'ret': False, 'msg': "Please specify reset_type in %s." % reset_scope}
                return result

            reset_url = result['entries']['Actions']['#Manager.Reset']['target']
            # Build request body and send requests to restart manager
            body = {}
            if reset_type != None:
                body = {'ResetType': reset_type}
            else:
                if 'GracefulRestart' in reset_scope:
                    body = {'ResetType': 'GracefulRestart'}
                elif 'ForceRestart' in reset_scope:
                    body = {'ResetType': 'ForceRestart'}
                else:
                    body = {"Action": "Manager.Reset"}

            # perform post to restart bmc
            headers = {"Content-Type":"application/json"}
            response = self.post(reset_url, headers=headers, body=body)
            if response.status in [200, 204]:
                result = {'ret': True, 'msg': "Succeed to reset bmc."}
            else:
 
                result = {'ret': False, 'msg': "Failed to reset bmc. Url: %s. Error code is %s. Error message is %s. " % \
                          (reset_url, response.status, response.text)}
                LOGGER.error(result['msg'])
            return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to reset bmc. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def set_bmc_ntp(self, ntp_server, protocol_enabled='1'):
        """Set bmc ntp server
        :params ntp_server: ntp server list
        :type ntp_server: list
        :params protocol_enabled: Enable NTP or not. 1: Enable, 0: Disable
        :type protocol_enabled: number
        :returns: returns the result to set bmc's ntp
        """
        result = {}
        try:
            manager_url = self._find_manager_resource()
            result = self._get_url(manager_url + '/NetworkProtocol')
            if result['ret'] == False:
                return result
            
            if 'NTP' not in result['entries']:
                result = {'ret': False, 'msg': "Failed to find NTP property."}
                return result
            
            if "@odata.etag" in result['entries']:
                etag = result['entries']['@odata.etag']
            else:
                etag = ""
            headers = {"If-Match": etag}
            
            # Build patch body for request set ntp servers
            protocol = {"NTPServers":ntp_server,"ProtocolEnabled":  bool(int(protocol_enabled))}
            body = {"NTP": protocol}
            response = self.patch(manager_url + '/NetworkProtocol', body=body, headers=headers)
            if response.status in [200,204]:
                result = {'ret': True, 'msg': "Succeed to set bmc's NTP servers."}
            else:
                LOGGER.error(str(response))
                result = {'ret': False, 'msg': "Failed to set bmc's NTP servers. Error code is %s. Error message is %s. " % \
                         (response.status, response.text)}
            return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to set bmc's NTP servers. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

manager_cmd_list = {
        "get_bmc_inventory": {
                'help': "Get bmc's inventory", 
                'args': []
        },
        "get_bmc_networkprotocol": {
                'help': "Get network services info of bmc",
                'args': []
        },
        "get_bmc_serialinterfaces": {
                'help': "Get serial interfaces of bmc",
                'args': []
        },
        "get_bmc_ethernet_interfaces": {
                'help': "Get nic info of bmc",
                'args': []
        },
        "get_bmc_virtual_media": {
                'help': "Get virtual media info of bmc",
                'args': []
        },
        "get_bmc_hostinterfaces": {
                'help': "Get host interfaces of bmc",
                'args': []
        },
        "get_bmc_ntp": {
                'help': "Get NTP setting of bmc",
                'args': []
        },
        "get_event_log": {
                'help': "Get event logs of manager, system or chassis",
                'args': [{'argname': "--type", 'type': str, 'nargs': "?", 'required': False, 'help': "Log of 'manager', 'system' or 'chassis', default is 'manager'"}]
        },
        "get_bmc_users": {
                'help': "Get user accounts of bmc",
                'args': []
        },
        "lenovo_create_bmc_user": {
                'help': "Add new user account of bmc",
                'args': [{'argname': "--username", 'type': str, 'nargs': "?", 'required': True, 'help': "New user's name"},
                         {'argname': "--password", 'type': str, 'nargs': "?", 'required': True, 'help': "New user's password"},
                         {'argname': "--authority", 'type': str, 'nargs': "*", 'required': True, 'help': "New user's authority, like 'Supervisor' or 'UserAccountManagement' 'RemoteConsoleAccess'"}]
        },
        "lenovo_delete_bmc_user": {
                'help': "Delete one user account of bmc",
                'args': [{'argname': "--username", 'type': str, 'nargs': "?", 'required': True, 'help': "User name will be deleted."}]
        },
        "set_bmc_networkprotocol": {
                'help': "Set network service of bmc, like: enable/disable service, or change the port",
                'args': [{'argname': "--service", 'type': str, 'nargs': "?", 'required': True, 'help': "Service name, like: 'IPMI', 'NTP'"},
                         {'argname': "--enabled", 'type': int, 'nargs': "?", 'required': False, 'help': "Enable/disable the service. 1: enable, 0: disable."},
                         {'argname': "--port", 'type': int, 'nargs': "?", 'required': False, 'help': "Port of network service"}]
        },
        "lenovo_export_ffdc": {
                'help': "Export FFDC data",
                'args': [{'argname': "--data_type", 'type': str, 'nargs': "?", 'required': False, 'help': "Data collection type: 'ProcessorDump', 'ServiceDataFile' or 'BootPOSTDump'. Default is 'ProcessorDump'. Only for XCC"},
                         {'argname': "--fsprotocol", 'type': str, 'nargs': "?", 'required': False, 'help': "Transfer protocol. For XCC: 'SFTP', 'TFTP' or None(local save). Fox TSM: 'HTTP' only"},
                         {'argname': "--fsip", 'type': str, 'nargs': "?", 'required': False, 'help': "File server's ip, like: SFTP or TFTP server ip"},
                         {'argname': "--fsport", 'type': int, 'nargs': "?", 'required': False, 'help': "File server's port, only for HTTP. Default is '8080'"},
                         {'argname': "--fsusername", 'type': str, 'nargs': "?", 'required': False, 'help': "User name to access SFTP file server"},
                         {'argname': "--fspassword", 'type': str, 'nargs': "?", 'required': False, 'help': "Password to access SFTP file server"},
                         {'argname': "--fsdir", 'type': str, 'nargs': "?", 'required': False, 'help': "full path of dir on file server(SFTP/TFTP) under which ffdc file will be saved. for HTTP file server, fsdir should be the path to HTTP service root."}]
        },
        "lenovo_mount_virtual_media": {
                'help': "Mount virtual media",
                'args': [{'argname': "--image", 'type': str, 'nargs': "?", 'required': True, 'help': "Image's file name"},
                         {'argname': "--fsprotocol", 'type': str, 'nargs': "?", 'required': False, 'help': "Transfer protocol. For XCC: 'HTTP' or 'NFS'. Fox TSM: 'NFS' only"},
                         {'argname': "--fsip", 'type': str, 'nargs': "?", 'required': False, 'help': "File server's ip, like: HTTP or NFS server ip"},
                         {'argname': "--fsdir", 'type': str, 'nargs': "?", 'required': False, 'help': "full path of dir on NFS server. for HTTP file server, fsdir should be the path to HTTP service root."},
                         {'argname': "--fsport", 'type': int, 'nargs': "?", 'required': False, 'help': "File server's port"},
                         {'argname': "--inserted", 'type': int, 'nargs': "?", 'required': False, 'help': "1 or 0. 1: True, 0: False"},
                         {'argname': "--write_protected", 'type': int, 'nargs': "?", 'required': False, 'help': "1 or 0. 1: True, 0: False"}]
        },
        "lenovo_umount_virtual_media": {
                'help': "Umount virtual media",
                'args': [{'argname': "--image", 'type': str, 'nargs': "?", 'required': True, 'help': "Image name, virtual media with this name will be ejected"}]
        },
        "lenovo_bmc_config_backup": {
                'help': "Back up the configuration of bmc",
                'args': [{'argname': "--backup_password", 'type': str, 'nargs': "?", 'required': True, 'help': "Backup password for encrypting configuration file"},
                         {'argname': "--backup_file", 'type': str, 'nargs': "?", 'required': False, 'help': "Backup file of configuration, only for XCC. Default is 'bmc_config_backup.json' under current working directory."},
                         {'argname': "--httpip", 'type': str, 'nargs': "?", 'required': False, 'help': "HTTP file server's ip, only for TSM"},
                         {'argname': "--httpport", 'type': int, 'nargs': "?", 'required': False, 'help': "HTTP file server's port, only for TSM"},
                         {'argname': "--httpdir", 'type': str, 'nargs': "?", 'required': False, 'help': "Path on HTTP file server to save the backup file, only for TSM"}]
        },
        "lenovo_bmc_config_restore": {
                'help': "Restore the configuration of bmc",
                'args': [{'argname': "--backup_password", 'type': str, 'nargs': "?", 'required': True, 'help': "Password for decrypting configuration file"},
                         {'argname': "--backup_file", 'type': str, 'nargs': "?", 'required': False, 'help': "Backup file of configuration, only for XCC. Default is 'bmc_config_backup.json' under current working directory."},
                         {'argname': "--httpip", 'type': str, 'nargs': "?", 'required': False, 'help': "HTTP file server's ip, only for TSM"},
                         {'argname': "--httpport", 'type': int, 'nargs': "?", 'required': False, 'help': "HTTP file server's port, only for TSM"},
                         {'argname': "--httpdir", 'type': str, 'nargs': "?", 'required': False, 'help': "Path on HTTP file server to save the backup file, only for TSM"}]
        },
        "reset_bmc": {
                'help': "Set one attribute of bios",
                'args': [{'argname': "--reset_type", 'type': str, 'nargs': "?", 'required': True, 'help': "for XCC: 'GracefulRestart' or 'ForceRestart'. for TSM: 'ForceRestart' only"}]
        },
        "set_bmc_ntp": {
                'help': "Set system's boot order",
                'args': [{'argname': "--ntp_server", 'type': str, 'nargs': "*", 'required': True, 'help': "NTP server list, like: '1.1.1.1' '2.2.2.2'"},
                         {'argname': "--protocol_enabled", 'type': int, 'nargs': "?", 'required': False, 'help': "Enable NTP or not. 1: Enable, 0: Disable"}]
        }
}

def add_manager_parameter(subcommand_parsers):    
    for func in manager_cmd_list.keys():
        parser_function = subcommand_parsers.add_parser(func, help=manager_cmd_list[func]['help'])
        for arg in manager_cmd_list[func]['args']:
            parser_function.add_argument(arg['argname'], type=arg['type'], nargs=arg['nargs'], required=arg['required'], help=arg['help'])

def run_manager_subcommand(args):
    """ return result of running subcommand """

    parameter_info = {}
    parameter_info = parse_common_parameter(args)

    cmd = args.subcommand_name
    if cmd not in manager_cmd_list.keys():
        result = {'ret': False, 'msg': "Subcommand is not correct."}
        usage()
        return result

    try:
        client = ManagerClient(ip=parameter_info['ip'], 
                                    username=parameter_info['user'], 
                                    password=parameter_info['password'], 
                                    configfile=parameter_info['config'], 
                                    auth=parameter_info['auth'])
        client.login()
    except Exception as e:
        LOGGER.debug("%s" % traceback.format_exc())
        msg = "Failed to login. Error message: %s" % (repr(e))
        LOGGER.debug(parameter_info)
        LOGGER.error(msg)
        return {'ret': False, 'msg': msg}

    result = {}
    if cmd == 'get_bmc_inventory':
        result = client.get_bmc_inventory()

    elif cmd == 'get_bmc_networkprotocol':
        result = client.get_bmc_networkprotocol()

    elif cmd == 'get_bmc_serialinterfaces':
        result = client.get_bmc_serialinterfaces()

    elif cmd == 'get_bmc_ethernet_interfaces':
        result = client.get_bmc_ethernet_interfaces()

    elif cmd == 'get_bmc_hostinterfaces':
        result = client.get_bmc_hostinterfaces()

    elif cmd == 'get_bmc_ntp':
        result = client.get_bmc_ntp()

    elif cmd == 'get_event_log':
        parameter_info["type"] = 'manager'
        if args.type:
            parameter_info["type"] = args.type
        result = client.get_event_log(parameter_info["type"])

    elif cmd == 'get_bmc_users':
        result = client.get_bmc_users()

    elif cmd == 'get_bmc_virtual_media':
        result = client.get_bmc_virtual_media()

    elif cmd == 'lenovo_create_bmc_user':
        parameter_info["username"] = args.username
        parameter_info["password"] = args.password
        parameter_info["authority"] = args.authority
        result = client.lenovo_create_bmc_user(parameter_info["username"], parameter_info["password"], parameter_info["authority"])

    elif cmd == 'lenovo_delete_bmc_user':
        parameter_info["username"] = args.username
        result = client.lenovo_delete_bmc_user(parameter_info["username"])

    elif cmd == 'set_bmc_networkprotocol':
        parameter_info["service"] = args.service
        parameter_info["enabled"] = args.enabled
        parameter_info["port"] = args.port
        result = client.set_bmc_networkprotocol(parameter_info["service"], parameter_info["enabled"], parameter_info["port"])

    elif cmd == 'lenovo_export_ffdc':
        parameter_info["data_type"] = args.data_type
        parameter_info["fsprotocol"] = args.fsprotocol
        parameter_info["fsip"] = args.fsip
        parameter_info["fsport"] = args.fsport
        parameter_info["fsdir"] = args.fsdir
        parameter_info["fsusername"] = args.fsusername
        parameter_info["fspassword"] = args.fspassword
        result = client.lenovo_export_ffdc(parameter_info["data_type"], parameter_info["fsprotocol"], parameter_info["fsip"], parameter_info["fsport"], parameter_info["fsdir"], parameter_info["fsusername"], parameter_info["fspassword"])

    elif cmd == 'lenovo_mount_virtual_media':
        parameter_info["image"] = args.image
        parameter_info["fsprotocol"] = args.fsprotocol
        parameter_info["fsip"] = args.fsip
        parameter_info["fsport"] = args.fsport
        parameter_info["fsdir"] = args.fsdir
        parameter_info["inserted"] = 1
        if args.inserted != None:
            parameter_info["inserted"] = args.inserted
        parameter_info["write_protected"] = 1
        if args.write_protected != None:
            parameter_info["write_protected"] = args.write_protected

        # Change to 'basic' session. If use 'session' connection, once logout, virtual media will be ejected automatically.
        client.login(auth='basic')
        result = client.lenovo_mount_virtual_media(parameter_info["image"], parameter_info["fsprotocol"], parameter_info["fsip"], parameter_info["fsdir"], parameter_info["fsport"], parameter_info["inserted"], parameter_info["write_protected"])

    elif cmd == 'lenovo_umount_virtual_media':
        parameter_info["image"] = args.image
        result = client.lenovo_umount_virtual_media(parameter_info["image"])

    elif cmd == 'lenovo_bmc_config_backup':
        parameter_info["backup_password"] = args.backup_password
        parameter_info["backup_file"] = args.backup_file
        parameter_info["httpip"] = args.httpip
        parameter_info["httpport"] = args.httpport
        parameter_info["httpdir"] = args.httpdir
        result = client.lenovo_bmc_config_backup(parameter_info["backup_password"], parameter_info["backup_file"], parameter_info["httpip"], parameter_info["httpport"], parameter_info["httpdir"])

    elif cmd == 'lenovo_bmc_config_restore':
        parameter_info["backup_password"] = args.backup_password
        parameter_info["backup_file"] = args.backup_file
        parameter_info["httpip"] = args.httpip
        parameter_info["httpport"] = args.httpport
        parameter_info["httpdir"] = args.httpdir
        result = client.lenovo_bmc_config_restore(parameter_info["backup_password"], parameter_info["backup_file"], parameter_info["httpip"], parameter_info["httpport"], parameter_info["httpdir"])

    elif cmd == 'reset_bmc':
        parameter_info["reset_type"] = args.reset_type
        result = client.reset_bmc(parameter_info["reset_type"])

    elif cmd == 'set_bmc_ntp':
        parameter_info["ntp_server"] = args.ntp_server
        parameter_info["protocol_enabled"] = 1
        if args.protocol_enabled != None:
            parameter_info["protocol_enabled"] = args.protocol_enabled
        result = client.set_bmc_ntp(parameter_info["ntp_server"], parameter_info["protocol_enabled"])

    else:
        result = {'ret': False, 'msg': "Subcommand is not supported."}

    client.logout()
    LOGGER.debug(parameter_info)
    LOGGER.debug(result)
    return result

def manager_usage():
    print("  Manager subcommands:")
    for cmd in manager_cmd_list.keys():
        print("    %-42s Help:  %-120s" % (cmd, manager_cmd_list[cmd]['help']))
        for arg in manager_cmd_list[cmd]['args']:
            print("                %-30s Help:  %-120s" % (arg['argname'], arg['help']))
    print('')
