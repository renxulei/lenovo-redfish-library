#!/usr/bin/python
###
#
# Lenovo Redfish Library - Sample of how to use lenovo redfish class.
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

import sys
import os
import json
import sys

from lenovo_redfish_library import *

if __name__ == "__main__":

    # Use ManagerClient to perform info collection and configuration related with BMC 
    client = ManagerClient(ip='10.245.39.251', username='renxulei', password='PASSW0RD12q')
    client.login()
    result = client.get_bmc_inventory()
    client.logout()
    
    # print result
    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))

    # Use SystemClient to perform info collection and configuration related with System 
    client = SystemClient(ip='10.245.39.251', username='renxulei', password='PASSW0RD12q')
    client.login()
    result = client.get_system_inventory()
    client.logout()
    
    # print result
    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))
