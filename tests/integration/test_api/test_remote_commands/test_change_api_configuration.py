from os import path

import requests

from wazuh_testing.api import get_api_details_dict, change_api_conf
from wazuh_testing.tools.services import control_service

configuration_files_path = path.join(path.dirname(path.abspath(__file__)), 'data')


# Tests
def test_change_configuration(restore_configurations):
    """Test if an API configuration `remote_commands` can be uploaded through the endpoint and manually."""
    api_details = get_api_details_dict()
    api_config_endpoint = f"{api_details['base_url']}/manager/api/config"
    upload_endpoint = f"{api_details['base_url']}/manager/files?path=etc/ossec.conf&overwrite=true&wait_for_complete=true"
    remote_config = {'remote_commands': {'localfile': {'enabled': 'no', 'exceptions': []}}}
    upload_headers = {'Content-Type': 'application/octet-stream',
                      'Authorization': api_details['auth_headers']['Authorization']}
    localfile_file = path.join(configuration_files_path, 'localfile_ossec.conf')

    # Try to change `remote_commands` configuration with API and expect it to deny it
    response = requests.put(api_config_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 400, f'Expected API to block remote_commands.\nFull response: {response.json()}'

    # Change `remote_commands` configuration manually
    change_api_conf(remote_config)
    control_service('restart')

    # Try to upload a config with commands on localfile
    response = requests.put(upload_endpoint, headers=upload_headers,
                            files={'file': open(localfile_file, 'rb').read()},
                            verify=False)
    assert response.status_code == 200, f'Expected status code 200.\nFull response: {response.json()}'
    try:
        assert response.json()['data']['failed_items'][0]['error']['code'] == 1124, f'Expected error 1124. \nFull response ' \
                                                                                 f"{response.json()}"
    except IndexError:
        raise IndexError(f'Expected failed item.\nFull response: {response.json()}')
