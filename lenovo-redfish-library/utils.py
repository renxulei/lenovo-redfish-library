###
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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


import sys, os
import argparse
import configparser
import logging

warnings.filterwarnings('ignore')

def redfish_logger(file_name, log_format, log_level=logging.ERROR):
    formatter = logging.Formatter(log_format)
    fh = logging.FileHandler(file_name)
    fh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(fh)
    logger.setLevel(log_level)
    return logger

#Config logger used by Lenovo Redfish Client
LOGGERFILE = "LenovoRedfishClient.log"
LOGGERFORMAT = "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s"
LOGGER = redfish_logger(LOGGERFILE, LOGGERFORMAT, logging.DEBUG)
#LOGGER = logging.getLogger(__name__)


""" example:
    data_chassis = {...}
    properties = ['Model', 'SerialNumber', 'Manufacturer', 'IndicatorLED', 'ChassisType',
                  'AssetTag', 'ProductName', 'Status/State', 'Status/Health']
    filtered_chassis = propertyFilter(data_chassis, properties)
"""

def propertyFilter(data, properties):
    if isinstance(data, dict):
        filtered_data = {}
        for property in properties:
            if property in data:
                filtered_data[property] = data[property]
            elif '/' in property: # cann't handle list in path, only can handle dict
                props = property.split('/')
                curdata = data
                prop_name = props[-1]
                for prop in props:
                    if prop in curdata:
                        curdata = curdata[prop]
                    else:
                        curdata = None
                        break
                filtered_data[prop_name] = curdata
            else:
                filtered_data[property] = None
                if 'Oem' in data and 'Lenovo' in data['Oem']:
                    if property in data['Oem']['Lenovo']:
                        filtered_data[property] = data['Oem']['Lenovo'][property]
        return filtered_data
    elif isinstance(data, list):
        filtered_data = list()
        for member in data:
            filtered_mem = {}
            for property in properties:
                if property in member:
                    filtered_mem[property] = member[property]
                elif '/' in property: # cann't handle list in path, only can handle dict
                    props = property.split('/')
                    curdata = member
                    prop_name = props[-1]
                    for prop in props:
                        if prop in curdata:
                            curdata = curdata[prop]
                        else:
                            curdata = None
                            break
                    filtered_mem[prop_name] = curdata
                else:
                    filtered_mem[property] = None
                    if 'Oem' in member and 'Lenovo' in member['Oem']:
                        if property in member['Oem']['Lenovo']:
                            filtered_mem[property] = member['Oem']['Lenovo'][property]
            filtered_data.append(filtered_mem)
        return filtered_data
    else:
        return data


def getPropertyValue(data, property):
    if isinstance(data, dict):
        if property in data:
            return data[property]
        elif '/' in property: # cann't handle list in path, only can handle dict
            props = property.split('/')
            curdata = data
            for prop in props:
                if prop in curdata:
                    curdata = curdata[prop]
                else:
                    curdata = None
                    break
            return curdata
        else:
            if 'Oem' in data and 'Lenovo' in data['Oem']:
                if property in data['Oem']['Lenovo']:
                    return data['Oem']['Lenovo'][property]
    return None

def read_config(config_file):
    """Read configuration file infomation    
    :config_file: Configuration file
    :type config_file: string 
    """
    
    cfg = configparser.ConfigParser()
    try:
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        if os.sep not in config_file:
            config_file = cur_dir + os.sep + config_file

        config_ini_info = {}
        cfg.read(config_file)
        connect_cfg_list = cfg.items(section='ConnectCfg')
        for item in connect_cfg_list:
            config_ini_info[item[0]] = item[1]
        fileserver_cfg_list = cfg.items(section='FileServerCfg')
        for item in fileserver_cfg_list:
            config_ini_info[item[0]] = item[1]
        result = {'ret': True, 'entries': config_ini_info}
    except Exception as e:
        result = {'ret': False, 'msg': "Failed to parse configuration file %s, Error is %s ." % (config_file, repr(e))}
        LOGGER.error('Error: in parsing file %s, problem line:\"%s\" found exception\n %s' %(filename, line, str(e)))
    return result