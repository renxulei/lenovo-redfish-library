###
#
# Lenovo Redfish Library - Main module for commandline supoort
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

from .utils import *
from .utils import add_common_parameter
from .utils import parse_common_parameter
from .system_client import *
from .manager_client import *
from .chassis_client import *
from .update_client import *
from .account_client import *


def usage():
    system_usage()
    manager_usage()
    chassis_usage()
    update_usage()
    account_usage()

def main(argv):
    """Lenovo Redfish client's main"""

    argget = argparse.ArgumentParser(description="Lenovo Redfish Tool")
    add_common_parameter(argget)
    
    subcommand_parsers = argget.add_subparsers(dest='subcommand_name', help='all subcommands')
    add_system_parameter(subcommand_parsers)
    add_manager_parameter(subcommand_parsers)
    add_chassis_parameter(subcommand_parsers)
    add_update_parameter(subcommand_parsers)
    add_account_parameter(subcommand_parsers)

    # Parse the parameters
    args = argget.parse_args()

    if args.subcommand_name in system_cmd_list.keys():
        result = run_system_subcommand(args)
    elif args.subcommand_name in manager_cmd_list.keys():
        result = run_manager_subcommand(args)
    elif args.subcommand_name in chassis_cmd_list.keys():
        result = run_chassis_subcommand(args)
    elif args.subcommand_name in update_cmd_list.keys():
        result = run_update_subcommand(args)
    elif args.subcommand_name in account_cmd_list.keys():
        result = run_account_subcommand(args)
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