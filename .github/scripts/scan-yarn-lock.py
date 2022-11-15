#!/bin/python

import json
import os
import requests
import logging
import yaml
import threading

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MICROSERVICE_PATH = os.environ.get("MICROSERVICE_PATH")
# ../../yarn.lock
YARN_LOCK_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(__file__))), 'yarn.lock')
CLIENT_ID = os.environ.get("PORT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("PORT_CLIENT_SECRET")
API_URL = 'https://api.getport.io/v1'
RUNTIME = os.environ.get("RUNTIME")
MAX_THREADS = 4
sema = threading.Semaphore(value=MAX_THREADS)


def create_package_entity_json(pName, pVer):
    """
    This function recives a Package name (pName) and a Package version (pVer), and returns
    a json containing a templated package enitity.

                    Port's 'identifier' property has a Regex pattern ('^[A-Za-z_][A-Za-z0-9@_-]*$').
                    Yarn lock uses symbols in the package name field, which we have to filter out.

                    For example, lets say we have a package in yarn.lock called "@aws-sdk/client-secrets-manager", with the version "^3.199.0".

                    The entities identifier would be: 'aws-sdk-client-secrets-manager-3_199_0',
                    and the entitie's title would be: '@aws-sdk/client-secrets-manager_^3.199.0'.

    Args:
                    pName (string): Package name
                    pVer (string): Package version

    Returns:
                    packacge-entity: Returns a json/dict object containing the templated package entity.
    """
    format_version = pVer.replace(".", "_").replace('^', '')
    format_name = pName.replace(".", "_").replace('/', '-').replace('@', '')
    package_entity = {
        "identifier": f"{format_name}-{format_version}",
        "title": f"{pName}_{pVer}",
        "blueprint": "Package",
        "properties": {
            "version": f"{pVer}"
        },
        "relations": {}
    }
    return package_entity


def get_port_api_token():
    """
    Returns:
    Get a Port API access token
    This function uses CLIENT_ID and CLIENT_SECRET from config
    """

    credentials = {'clientId': CLIENT_ID, 'clientSecret': CLIENT_SECRET}

    token_response = requests.post(
        f"{API_URL}/auth/access_token", json=credentials)

    return token_response.json()['accessToken']


def create_port_entity(blueprint, entity_json, token):
    """
            Reports to Port on a new entity based on provided `entity_json'.
            Uses threading to parallel-create the package entities in  Port.

            Args:
                    blueprint: Blueprint name (type of entity to create)
                    entity_json: Json of the entity to create
                    token: PortAPI Token

            Return:
                    Status code of POST command sent to Port
    """
    sema.acquire()
    logger.info('Fetching token')

    headers = {
        'Authorization': f'Bearer {token}'
    }
    params = {
        'upsert': 'true'
    }
    logger.info('Creating entity:')
    logger.info(json.dumps(entity_json))
    response = requests.post(f'{API_URL}/blueprints/{blueprint}/entities',
                             json=entity_json, headers=headers, params=params)
    logger.info(response.status_code)
    logger.info(response.json())
    if response.status_code == 200 or response.status_code == 201:
        print(f"Created/Updated {entity_json['identifier']} {blueprint}!")
    else:
        logger.warning(
            f"Failed to create {entity_json['identifier']} {blueprint}")
    sema.release()
    return response.status_code


def get_port_entity(blueprint, identifier, token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    logger.info('Getting entity:')
    response = requests.get(
        f'{API_URL}/blueprints/{blueprint}/entities/{identifier}', headers=headers)
    logger.info(response.status_code)
    logger.info(response.json())
    return response.json(), response.status_code


def get_deploy_config(ms_name, token):
    """
    This function warps get_port_entity, and get specifically, a deployment config with the identifier
    'ms_name-RUNTIME'.

    Args:
                    ms_name (string): Microservice name
                    token (string): PortAPI token

    Returns:
                    dc_entity:
    """
    identifier = f"{ms_name}-{RUNTIME}"
    deployment_config, status = get_port_entity(
        "DeploymentConfig", identifier, token)
    if status != 200 and status != 201:
        print(f"DeploymentConfig named {identifier} doesn't exist!")
        return None
    dc_entity = deployment_config['entity']
    # Must supply title field
    if dc_entity['title'] is None:
        dc_entity['title'] = identifier
    # Remove old packages from deployment config
    dc_entity['relations']['package'].clear()
    return dc_entity


def create_packages_for_dc(ms_name, token, yarn_dict):
    """
    Looks for all the packages related to 'ms_name' in the yarn lock(yarn_dict),
    and creates co-responding package in Port.

    Args:
                    ms_name (string): Micorservice name
                    token (string): Result of get_port_api_token()
                    yarn_dict (dict): Dict of the yarn.lock file

    Returns:
                    dict: Will return a dict consisting of a "DeploymentConfig" port entity, with the updated packages.
                                            If the requested "DeploymentConfig" entity doesn't exist, return None.
    """
    print(
        f"########## Creating Package entities for {ms_name} DeploymentConfig! ##########")
    dc_entity = get_deploy_config(ms_name, token)
    if dc_entity is None:
        return dc_entity
    report_threads = []
    for package in yarn_dict[f'{ms_name}@workspace:{MICROSERVICE_PATH}{ms_name}']["dependencies"]:
        # In yarn.lock, dependencies only show minimum version
        ver_minimum = yarn_dict[f'{ms_name}@workspace:{MICROSERVICE_PATH}{ms_name}']["dependencies"][
            package]
        # If 2 packages exist with different version, keep both.
        try:
            package_ver = yarn_dict[f"{package}@npm:{ver_minimum}"]["version"]
        except KeyError:
            package_ver = ver_minimum
        package_entity = create_package_entity_json(package, package_ver)
        report_thread = threading.Thread(
            target=create_port_entity, args=("Package", package_entity, token))
        report_thread.start()
        report_threads.append(report_thread)
        # Add package to entities relation.package dictionary
        dc_entity['relations']['package'].append(
            package_entity['identifier'])
    for thread in report_threads:
        thread.join()
    return dc_entity


def main():
    token = get_port_api_token()
    yarn_dict = {}
    with open(YARN_LOCK_PATH) as f:
        yarn_dict = yaml.full_load(f)
    # we presume that the dir_name == microservice_id in MICROSERVICE_PATH dir
    for ms_name in os.listdir(MICROSERVICE_PATH):
        dc_entity = create_packages_for_dc(ms_name, token, yarn_dict)
        if dc_entity is not None:
            create_port_entity("DeploymentConfig", dc_entity, token)


if __name__ == '__main__':
    main()
