###
#
# Lenovo Redfish Library - AccountClient Class
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

import traceback 

from .redfish_base import RedfishBase
from .utils import *
from .utils import add_common_parameter
from .utils import parse_common_parameter

class AccountClient(RedfishBase):
    """A client for managing accounts"""

    def __init__(self, ip='', username='', password='',
                 configfile='config.ini', auth=''):
        """Initialize AccountClient"""

        super(AccountClient, self).__init__(
            ip=ip, username=username, password=password, 
            configfile=configfile, auth=auth
        )

    #############################################
    # functions for getting information.
    #############################################

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

    #############################################
    # functions for setting information.
    #############################################

    def _check_bmc_type(self):
        manager_url = self._find_manager_resource()
        bmc_type = 'TSM' if 'Self' in manager_url else 'XCC'
        return bmc_type

    PRIVILEGES_XCC = [
        "UserAccountManagement",
        "RemoteConsoleAccess",
        "RemoteConsoleAndVirtualMediaAccess",
        "RemoteServerPowerRestartAccess",
        "AbilityClearEventLogs",
        "Configuration_Basic",
        "Configuration_NetworkingAndSecurity",
        "Configuration_Advanced",
        "Configuration_UEFISecurity"
    ]

    PRIVILEGES_TSM = [
        "Login",
        "ConfigureManager",
        "ConfigureSelf",
        "ConfigureUsers",
        "ConfigureComponents"
    ]

    def lenovo_create_bmc_role(self, role, privileges):
        """Create new role of bmc user 
        :params role: new role id
        :type password: string
        :params privileges: privileges list of role, like ['Supervisor'] or ['UserAccountManagement', 'RemoteConsoleAccess']
        :type privileges: list
        :returns: returns result of creating bmc role.
        """
        result = {}
        try:
            roles_url = '/redfish/v1/AccountService/Roles'
            response = self.get(roles_url)
            post_flag = False
            for item in response.getheaders():
                if item[0].upper() == 'ALLOW' and 'POST' in item[1].upper():
                    post_flag = True
                    break
            if post_flag == False:
                return {'ret': False, 'msg': "This version of bmc does not support adding new role."}
             
            bmc_type = self._check_bmc_type()
            
            # Check if privileges are correct.
            privileges_allowable = None  
            if bmc_type == 'XCC':
                privileges_allowable = self.PRIVILEGES_XCC
            else:
                privileges_allowable = self.PRIVILEGES_TSM

            for item in privileges:
                if item not in privileges_allowable:
                    return {'ret': False, 'msg': "Please specify correct privileges. Allowable privileges are %s." % privileges_allowable}

            # Prepare body for creating role
            parameter = {}
            if bmc_type == 'XCC':
                parameter = {
                    "RoleId": role,
                    "OemPrivileges": privileges
                }
            else:
                parameter = {
                    "Name": role,
                    "RoleId": role,
                    "AssignedPrivileges": privileges
                }

            #create new role
            headers = None
            response = self.post(roles_url, body=parameter, headers=headers)
            if response.status in [200, 201, 202, 204]:
                return {'ret': True, 'msg': "Succeed to create new role '%s'." % role}
            else:
                LOGGER.error(str(response))
                return {'ret': False, 'msg': "Failed to create new role '%s'. Error code is %s. Error message is %s. " % \
                        (role, response.status, response.text)}
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to create new role. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def lenovo_create_bmc_user(self, username, password, role, privileges=None):
        """Create new bmc user account
        :params username: new  username
        :type username: string
        :params password: new password
        :type password: string
        :params role: role name, like 'Administrator', 'Operator', 'ReadOnly' or other self-defined role name. If self-defined role name is specified, please ensure this role exist or privileges must be specified.
        :type password: string
        :params privileges: user privileges list, like ['Supervisor'] or ['UserAccountManagement', 'RemoteConsoleAccess']
        :type privileges: list
        :returns: returns result of creating bmc user account.
        """
        result = {}
        try:
            accounts_url = '/redfish/v1/AccountService/Accounts'
            
            response = self.get(accounts_url)
            post_flag = False
            for item in response.getheaders():
                if item[0].upper() == 'ALLOW' and 'POST' in item[1].upper():
                    post_flag = True
                    break

            # Set user role
            # for TSM, accept 'Supervisor', 'Administrator', 'Operator' and 'ReadOnly'
            # for XCC, accept 'Supervisor', 'Administrator', 'Operator', 'ReadOnly' or self-defined role 
            role_predefined = ['Administrator', 'Operator', 'ReadOnly']
            if role == "Supervisor":
                role = "Administrator"

            parameter = {}
            if post_flag == True:
                # Check self-defined role exist.
                roles_url = '/redfish/v1/AccountService/Roles'
                if role not in role_predefined:
                    found_flag = False
                    result = self._get_collection(roles_url)
                    if result['ret'] == False:
                        return result
                    for member in result['entries']:
                        if role == member['Id']:
                            found_flag = True
                            break
                    if found_flag == False:
                        if privileges == None:
                            return {'ret': False, 'msg': "The role '%s' does not exist." % role}
                        else: # create new role with the privileges specified
                            result = self.lenovo_create_bmc_role(role, privileges)
                            if result['ret'] == False:
                                return result

                #create new user account
                headers = None
                parameter = {
                    "Name": username,
                    "UserName": username,
                    "Password": password,
                    "RoleId": role
                }
                response = self.post(accounts_url, body=parameter, headers=headers)
                if response.status in [200, 201, 202, 204]:
                    account_id = response.dict['Id']
                    return {'ret': True, 'msg': "Succeed to create new user '%s'. Account id is '%s'." % (username, account_id)}
                else:
                    LOGGER.error(str(response))
                    return {'ret': False, 'msg': "Failed to create new user '%s'. Error code is %s. Error message is %s. " % \
                            (username, response.status, response.text)}
            
            else: # PATCH
                result = self._get_collection('/redfish/v1/AccountService/Accounts')
                if result['ret'] == False:
                    return result

                # Find first empty account
                account = None
                for member in result['entries']:
                    if member['UserName'] == username:
                        return {'ret': False, 'msg': "Failed to create new user. User '%s' existed." % username}
                    if member['UserName'] == '' or member['UserName'] == None:
                        account = member
                        break
                if account == None:
                    return {'ret': False, 'msg': "Accounts are full."}
                
                if role in role_predefined:
                    if 'RoleId@Redfish.AllowableValues' in account.keys(): # 20C
                        parameter = {
                            "UserName": username,
                            "Password": password,
                            "RoleId": role
                        }
                    else: # 20B and before
                        if role.lower() == 'operator':
                            return {'ret': False, 'msg': "This version of bmc does not support role 'Operator'. "}
                        parameter = {
                            "UserName": username,
                            "Password": password,
                            "RoleId": role
                        }
                else: # customize role
                    if privileges == None:
                        return {'ret': False, 'msg': "Please specify the privileges."}

                    role_url = account["Links"]["Role"]["@odata.id"]
                    result_role = self._get_url(role_url)
                    if result_role['ret'] == False:
                        return result_role
                    
                    privileges_allowable = None
                    if 'OemPrivileges@Redfish.AllowableValues' in result_role['entries'].keys():
                        privileges_allowable = result_role['entries']['OemPrivileges@Redfish.AllowableValues']
                    
                    if privileges_allowable == None:
                        bmc_type = self._check_bmc_type()
                        if bmc_type == 'XCC':
                            privileges_allowable = self.PRIVILEGES_XCC
                        else:
                            privileges_allowable = self.PRIVILEGES_TSM
                    
                    if privileges_allowable != None:
                        for item in privileges:
                            if item not in privileges_allowable:
                                return {'ret': False, 'msg': "Please specify correct privileges. Allowable privileges are %s." % privileges_allowable}

                    parameter = {
                        "OemPrivileges": privileges
                    }
                    patch_response = self.patch(role_url, body=parameter)
                    if patch_response.status not in [200, 204]:
                        result = {'ret': False, 'msg': "Failed to set the privileges. \
                                  Error code is %s. Error message is %s. " % \
                                  (patch_response.status, patch_response.text)}
                        return result
                    parameter = {
                        "UserName": username,
                        "Password": password
                    }
                
                # create new user
                account_url = account['@odata.id']
                if "@odata.etag" in account:
                    etag = account['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}

                response = self.patch(account_url, body=parameter, headers=headers)
                if response.status in [200, 204]:
                    result = {'ret': True, 'msg': "Succeed to create new user '%s'. Account id is '%s'." % (username, account['Id'])}
                    return result
                else:
                    LOGGER.error(str(response))
                    result = {'ret': False, 'msg': "Failed to create new user '%s'. Error code is %s. Error message is %s. " % \
                             (username, response.status, response.text)}
                    return result
        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to create bmc's user accounts. Error message: %s" % repr(e)
            LOGGER.error(msg)
            return {'ret': False, 'msg': msg}

    def delete_bmc_user(self, username):
        """delete one bmc user account
        :params username: bmc user name deleted
        :type username: string
        :returns: returns result of deleting bmc user account.
        """
        result = {}
        try:
            result = self._get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account = None
            for member in result['entries']:
                if member["UserName"] == username:
                    account = member
                    break

            if account == None:
                result = {'ret': False, 'msg': "The user '%s' specified does not exist." % username}
                LOGGER.error(result['msg'])
                return result

            account_url = account['@odata.id']
            response = self.get(account_url)
            delete_flag = False
            for item in response.getheaders():
                if item[0].upper() == 'ALLOW' and 'DELETE' in item[1].upper():
                    delete_flag = True
                    break

            if "@odata.etag" in account:
                etag = account['@odata.etag']
            else:
                etag = ""

            response = {}
            if delete_flag == True:
                headers = {"If-Match": "*" }
                response = self.delete(account_url, headers=headers)
            else: # use patch
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

        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to delete bmc's user. Error message: %s" % repr(e)
            LOGGER.error(msg)
            result = {'ret': False, 'msg': msg}
            return result

    def update_bmc_user_password(self, username, password):
        """Update one bmc user's password. If you want to update the password for first-access, please use update_default_password.
        :params username: bmc user name for password updating
        :type username: string
        :params password: new password
        :type password: string
        :returns: returns result of updating password.
        """
        result = {}
        try:
            result = self._get_collection('/redfish/v1/AccountService/Accounts')
            if result['ret'] == False:
                return result

            account = None
            for member in result['entries']:
                if member["UserName"] == username:
                    account = member
                    break

            if account == None:
                result = {'ret': False, 'msg': "The user '%s' specified does not exist." % username}
                LOGGER.error(result['msg'])
                return result

            account_url = account['@odata.id']
            if "@odata.etag" in account:
                etag = account['@odata.etag']
            else:
                etag = ""

            headers = {"If-Match": etag}
            body = {"Password": password}
            response = self.patch(account_url, body=body, headers=headers)
                                    
            if response.status in [200, 204]:
                result = {'ret': True, 'msg': "Succeed to update the password of user '%s'." % username}
                return result
            else:
                LOGGER.error(str(response))
                result = {'ret': False, 'msg': "Failed to update the password of user '%s'. Error code is %s. Error message is %s. " % \
                         (username, response.status, response.text)}
                return result

        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to update the password. Error message: %s" % repr(e)
            LOGGER.error(msg)
            result = {'ret': False, 'msg': msg}
            return result

    def update_default_password(self, password, account_id='1'):
        """update default account USERID's password or update the password of one bmc account for first access.
        :params password: new password
        :type password: string
        :params account_id: account id which password be updated. You can get it by get_bmc_user. Default is 1, id of 'USERID'.
        :type account_id: string
        :returns: returns result of updating password.
        """
        result = {}
        try:
            account_url = '/redfish/v1/AccountService/Accounts' + '/' + account_id
            headers = {"If-Match": "*"}
            body = {"Password": password}
            response = self.patch(account_url, body=body, headers=headers)
            if response.status in [200, 204]:
                result = {'ret': True, 'msg': "Succeed to update the password for account id '%s'." % account_id}
                return result
            else:
                LOGGER.error(str(response))
                result = {'ret': False, 'msg': "Failed to update the password for account id '%s'. Error code is %s. Error message is %s. " % \
                         (account_id, response.status, response.text)}
                return result

        except Exception as e:
            LOGGER.debug("%s" % traceback.format_exc())
            msg = "Failed to update the password. Error message: %s" % repr(e)
            LOGGER.error(msg)
            result = {'ret': False, 'msg': msg}
            return result

account_cmd_list = {
        "get_bmc_users": {
                'help': "Get user accounts of bmc",
                'args': []
        },
        "lenovo_create_bmc_role": {
                'help': "Add new role of bmc",
                'args': [{'argname': "--role", 'type': str, 'nargs': "?", 'required': True, 'help': "new role id: self-defined role name."},
                         {'argname': "--privileges", 'type': str, 'nargs': "*", 'required': False, 'help': "New role's privileges, like 'UserAccountManagement' 'RemoteConsoleAccess'"}]
        },
        "lenovo_create_bmc_user": {
                'help': "Add new user account of bmc",
                'args': [{'argname': "--username", 'type': str, 'nargs': "?", 'required': True, 'help': "New user's name"},
                         {'argname': "--password", 'type': str, 'nargs': "?", 'required': True, 'help': "New user's password"},
                         {'argname': "--role", 'type': str, 'nargs': "?", 'required': True, 'help': "User's role: 'Administrator', 'Operator', 'ReadOnly' or other self-defined role name. If self-defined role name is specified, please ensure the role exists or specify the privileges."},
                         {'argname': "--privileges", 'type': str, 'nargs': "*", 'required': False, 'help': "New user's privileges, like 'UserAccountManagement' 'RemoteConsoleAccess'"}]
        },
        "update_bmc_user_password": {
                'help': "Update one bmc user's password. If you want to update the password for first-access, please use update_default_password command",
                'args': [{'argname': "--username", 'type': str, 'nargs': "?", 'required': True, 'help': "User name for password updating"},
                         {'argname': "--password", 'type': str, 'nargs': "?", 'required': True, 'help': "New password"}]
        },
        "update_default_password": {
                'help': "Update one bmc user's password. If you want to update the password for first-access, please use update_default_password command",
                'args': [{'argname': "--password", 'type': str, 'nargs': "?", 'required': True, 'help': "New password"},
                         {'argname': "--account_id", 'type': str, 'nargs': "?", 'required': False, 'help': "Account id. Default is 1, id of user 'USERID'."}]
        },
        "delete_bmc_user": {
                'help': "Delete one user account of bmc",
                'args': [{'argname': "--username", 'type': str, 'nargs': "?", 'required': True, 'help': "User with this name will be deleted."}]
        }
}

def add_account_parameter(subcommand_parsers):    
    for func in account_cmd_list.keys():
        parser_function = subcommand_parsers.add_parser(func, help=account_cmd_list[func]['help'])
        for arg in account_cmd_list[func]['args']:
            parser_function.add_argument(arg['argname'], type=arg['type'], nargs=arg['nargs'], required=arg['required'], help=arg['help'])

def run_account_subcommand(args):
    """ return result of running subcommand """

    parameter_info = {}
    parameter_info = parse_common_parameter(args)

    cmd = args.subcommand_name
    if cmd not in account_cmd_list.keys():
        result = {'ret': False, 'msg': "Subcommand is not correct."}
        usage()
        return result

    try:
        client = AccountClient(ip=parameter_info['ip'], 
                               username=parameter_info['user'], 
                               password=parameter_info['password'], 
                               configfile=parameter_info['config'], 
                               auth=parameter_info['auth'])

        # Regarding updating password of default account or first access, 
        # we must use 'basic' auth because the account can not be 
        # used to setup session connection anymore until password updated.
        if cmd == 'update_default_password':
            client.login(auth='basic')
        else:
            client.login()
    except Exception as e:
        LOGGER.debug("%s" % traceback.format_exc())
        msg = "Failed to login. Error message: %s" % (repr(e))
        LOGGER.debug(parameter_info)
        LOGGER.error(msg)
        return {'ret': False, 'msg': msg}

    result = {}
    if cmd == 'get_bmc_users':
        result = client.get_bmc_users()

    elif cmd == 'lenovo_create_bmc_role':
        result = client.lenovo_create_bmc_role(args.role, args.privileges)

    elif cmd == 'lenovo_create_bmc_user':
        result = client.lenovo_create_bmc_user(args.username, args.password, args.role, args.privileges)

    elif cmd == 'update_bmc_user_password':
        result = client.update_bmc_user_password(args.username, args.password)

    elif cmd == 'update_default_password':
        if args.account_id == None:
            args.account_id = '1'
        result = client.update_default_password(args.password, args.account_id)

    elif cmd == 'delete_bmc_user':
        result = client.delete_bmc_user(args.username)

    else:
        result = {'ret': False, 'msg': "Subcommand is not supported."}

    client.logout()
    LOGGER.debug(args)
    LOGGER.debug(result)
    return result

def account_usage():
    print("  Account subcommands:")
    for cmd in account_cmd_list.keys():
        print("    %-42s Help:  %-120s" % (cmd, account_cmd_list[cmd]['help']))
        for arg in account_cmd_list[cmd]['args']:
            print("                %-30s Help:  %-120s" % (arg['argname'], arg['help']))
    print('')
