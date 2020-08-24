###
#
# Lenovo Redfish examples - Lenovo Redfish Tool
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
import argparse
import os
import json

from utils import *
from utils import add_common_parameter
from utils import parse_common_parameter
import system_client
import manager_client
import chassis_client
import update_client


def usage():
    system_client.usage()
    manager_client.usage()
    chassis_client.usage()
    update_client.usage()

def main(argv):
    """Lenovo Redfish client's main"""

    argget = argparse.ArgumentParser(description="Lenovo Redfish Tool")
    add_common_parameter(argget)
    
    subcommand_parsers = argget.add_subparsers(dest='subcommand_name', help='all subcommands')
    system_client.add_sub_parameter(subcommand_parsers)
    manager_client.add_sub_parameter(subcommand_parsers)
    chassis_client.add_sub_parameter(subcommand_parsers)
    update_client.add_sub_parameter(subcommand_parsers)

    # Parse the parameters
    args = argget.parse_args()

    if args.subcommand_name in system_client.cmd_list.keys():
        result = system_client.run_subcommand(args)
    elif args.subcommand_name in manager_client.cmd_list.keys():
        result = manager_client.run_subcommand(args)
    elif args.subcommand_name in chassis_client.cmd_list.keys():
        result = chassis_client.run_subcommand(args)
    elif args.subcommand_name in update_client.cmd_list.keys():
        result = update_client.run_subcommand(args)
    else:
        usage()
        result = {'ret': False, 'msg': "Please specify correct subcommand."}

    if 'msg' in result:
        print(result['msg'])
    if 'entries' in result:
        print(json.dumps(result['entries'], sort_keys=True, indent=2))
    if result['ret'] == False:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":

    main(sys.argv)