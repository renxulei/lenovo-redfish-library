#!/usr/bin/python
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

import sys
import os
import json

#sys.path.append(os.path.dirname(os.path.abspath(__file__)) + os.sep + 'lenovo_redfish_library')

from lenovo_redfish_library.main import main
from lenovo_redfish_library.manager_client import ManagerClient
import sys

if __name__ == "__main__":
    client = ManagerClient(ip='10.245.39.251', username='renxulei', password='PASSW0RD12q')
    client.login()
    result = client.get_bmc_inventory()
    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))    

    main(sys.argv)
