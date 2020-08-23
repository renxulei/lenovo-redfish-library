###
#
# Lenovo Redfish Client - Update Client
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

from redfish_base import RedfishBase
from utils import *
from utils import add_common_parameter
from utils import parse_common_parameter

class UpdateClient(RedfishBase):
    """A client for updating firmware"""

    def __init__(self, ip='', username='', password='',
                 configfile='config.ini', auth=''):
        """Initialize UpdateClient"""

        super(UpdateClient, self).__init__(
            ip=ip, username=username, password=password, 
            configfile=configfile, auth=auth
        )

    #############################################
    # functions for getting information.
    #############################################
 
    def get_firmware_inventory(self):
        """Get firmware inventory
        :returns: returns List of firmwares when succeeded or error message when failed
        """
        try:
            result = self._get_url('/redfish/v1/UpdateService')
            if result['ret'] == False:
                return result

            fw_url = result['entries']['FirmwareInventory']['@odata.id']
            result = self._get_collection(fw_url)
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

    #############################################
    # functions for updating firmware.
    #############################################

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
            manager_url = self._find_manager_resource()
            bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
            
            result = self._get_url('/redfish/v1/UpdateService')
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
                    if self._auth == 'session':
                        headers["X-Auth-Token"] = self.get_session_key()
                    else:
                        headers["Authorization"] = self.get_authorization_key()
                    files = {'data-binary':open(file_path,'rb')}
                    if self._cafile is not None and self._cafile != "":
                        response = requests.post(firmware_update_url, headers=headers, files=files, verify=self._cafile)
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
                    print("Start to refresh the firmware, please wait about 3~10 minutes...")
                    result = self._task_monitor(task_uri)
                    if result['ret'] == True:
                        result['msg'] = "Succeed to update the firmware. Image is '%s'." % image
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
                    if self._auth == 'session':
                        headers["X-Auth-Token"] = self.get_session_key()
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
                            result = {'ret': True, 'msg': "Succeed to update bmc. Image is '%s'. Wait about 5 minutes for bmc to restart." % image, 'task': task_uri}
                            return result
                        else:
                            task_uri = response.headers['Location']
                            print("Start to refresh the firmware, please wait about 3~10 minutes...")
                            result = self._task_monitor(task_uri)
                            if result['ret'] == True:
                                result['msg'] = "Succeed to update the firmware. Image is '%s'." % image
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

cmd_list = {
        "get_firmware_inventory": {
                'help': "Get firmware's inventory", 
                'args': []
        },
        "lenovo_update_firmware": {
                'help': "Update firmware",
                'args': [{'argname': "--image", 'type': str, 'nargs': "?", 'required': True, 'help': "Image's file name"},
                         {'argname': "--target", 'type': str, 'nargs': "?", 'required': False, 'help': "For XCC: 'BMC-Backup' only. For TSM: 'BMC' or 'UEFI'"},
                         {'argname': "--fsprotocol", 'type': str, 'nargs': "?", 'required': False, 'help': "Transfer protocol. For XCC: 'HTTPPUSH', 'SFTP' or 'TFTP'. Fox TSM: 'HTTPPUSH' only"},
                         {'argname': "--fsip", 'type': str, 'nargs': "?", 'required': False, 'help': "File server's ip, like: SFTP or TFTP server ip"},
                         {'argname': "--fsdir", 'type': str, 'nargs': "?", 'required': False, 'help': "Full path of dir on file server(SFTP/TFTP) or local machine(HTTPPUSH), under which image is saved."},
                         {'argname': "--fsusername", 'type': str, 'nargs': "?", 'required': False, 'help': "User name to access SFTP file server"},
                         {'argname': "--fspassword", 'type': str, 'nargs': "?", 'required': False, 'help': "Password to access SFTP file server"}]
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
        client = UpdateClient(ip=parameter_info['ip'], 
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
    if cmd == 'get_firmware_inventory':
        result = client.get_firmware_inventory()

    elif cmd == 'lenovo_update_firmware':
        parameter_info["image"] = args.image
        parameter_info["target"] = args.target
        parameter_info["fsprotocol"] = 'HTTPPUSH'
        if args.fsprotocol:
            parameter_info["fsprotocol"] = args.fsprotocol
        parameter_info["fsip"] = args.fsip
        parameter_info["fsdir"] = args.fsdir
        parameter_info["fsusername"] = args.fsusername
        parameter_info["fspassword"] = args.fspassword
        result = client.lenovo_update_firmware(parameter_info["image"], 
                                               parameter_info["target"], 
                                               parameter_info["fsprotocol"], 
                                               parameter_info["fsip"], 
                                               parameter_info["fsdir"], 
                                               parameter_info["fsusername"], 
                                               parameter_info["fspassword"])
    else:
        result = {'ret': False, 'msg': "Subcommand is not supported."}

    client.logout()
    return result


def usage():
    print("  Update subcommands:")
    for cmd in cmd_list.keys():
        print("    %-42s Help:  %-120s" % (cmd, cmd_list[cmd]['help']))
        for arg in cmd_list[cmd]['args']:
            print("                %-30s Help:  %-120s" % (arg['argname'], arg['help']))
    print('')

def main(argv):
    """Lenovo update client's main"""

    argget = argparse.ArgumentParser(description="Lenovo Redfish Tool - Update Client")
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

    # AMD
    #image_uefi = "lnvgy_fw_uefi_cfe117k-5.10_anyos_32-64.rom"
    #image_bmc = "lnvgy_fw_bmc_ambt11n-2.53_anyos_arm.hpm"
    #fsdir = "D:\\Workdata20190427\\work\\Task\\46-Redfish\\FW-Package\\20C\\AMD"
    #result = lenovo_redfish.lenovo_update_firmware(image=image_uefi, target='UEFI', fsdir=fsdir)
    #result = lenovo_redfish.lenovo_update_firmware(image=image_bmc, target='BMC', fsdir=fsdir)