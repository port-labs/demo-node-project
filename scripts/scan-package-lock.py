#!/bin/python

import json
import os
import requests
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ../package-lock.json 
PACKAGE_JSON_LOCK_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'package-lock.json')
CLIENT_ID = os.environ.get("PORT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("PORT_CLIENT_SECRET")

API_URL = 'https://api.getport.io/v1'

def create_package_entity_json(pName, pVer):
    # identifier cannot contain '.'
    format_version=pVer.replace(".", "_")
    format_name=pName.replace(".", "_")
    package_entity = {
    "identifier": f"{format_name}-{format_version}",
    "title": f"{pName}",
    "blueprint": "Package",
    "properties": {
      "version": f"{pVer}"
    },
    "relations": {}
    }
    return package_entity

def get_port_api_token():
    """
    Get a Port API access token
    This function uses CLIENT_ID and CLIENT_SECRET from config
    """

    credentials = {'clientId': CLIENT_ID, 'clientSecret': CLIENT_SECRET}

    token_response = requests.post(f"{API_URL}/auth/access_token", json=credentials)

    return token_response.json()['accessToken']

def report_to_port(blueprint, entity_json):
    '''
    Reports to Port on a new entity based on provided ``entity_props``
    '''
    logger.info('Fetching token')
    token = get_port_api_token()

    headers = {
        'Authorization': f'Bearer {token}'
    }
    params={
        'upsert': 'true'
    }
    logger.info('Creating entity:')
    logger.info(json.dumps(entity_json))
    response = requests.post(f'{API_URL}/blueprints/{blueprint}/entities', json=entity_json, headers=headers, params=params)
    logger.info(response.status_code)
    logger.info(json.dumps(response.json()))
    return response.status_code

def get_port_entity(blueprint, id):
    '''
    Gets Port entity using blueprint and id
    '''
    logger.info('Fetching token')
    token = get_port_api_token()

    headers = {
        'Authorization': f'Bearer {token}'
    }
    logger.info('Getting entity:')
    response = requests.get(f'{API_URL}/blueprints/{blueprint}/entities/{id}', headers=headers)
    logger.info(response.status_code)
    logger.info(json.dumps(response.json()))
    return json.dumps(response.json())

def main():
    package_lock = open(PACKAGE_JSON_LOCK_PATH, 'r')
    package_lock_json = json.load(package_lock)
    
    microservice = get_port_entity("micro", os.environ.get('MICROSERVICE_ID') )
    microservice = json.loads(microservice)
    ms_entity = microservice['entity']
    # Must supply title field
    if ms_entity['title'] == None:
        ms_entity['title'] = ""
    # Remove old packages from microservice
    ms_entity['relations']['package'].clear()
    
    # Fetch version for each installed parent package
    for package in package_lock_json["packages"][""]["dependencies"]:
        package_ver = package_lock_json['packages'][f'node_modules/{package}']['version']
        package_entity = create_package_entity_json(package, package_ver)
        report_to_port("Package",package_entity)
        print(f"Created {package.replace('.','_')}-{package_ver.replace('.','_')} package!")
        # Update microservice relations array
        ms_entity['relations']['package'].append(f"{package.replace('.','_')}-{package_ver.replace('.','_')}")
    report_to_port("micro", ms_entity)
    print(f"Updated {os.environ.get('MICROSERVICE_ID')} micro!")
    package_lock.close()

main()
