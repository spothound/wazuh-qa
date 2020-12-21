import requests

from wazuh_testing.api import get_api_details_dict, change_api_conf, check_api_config_file


# Tests
def test_restore_default_configuration(restore_configurations):
    """Test if the `remote_commands` section in the API configuration is removed after restoring the configuration to
    default using the endpoint."""
    api_details = get_api_details_dict()
    restore_endpoint = f"{api_details['base_url']}/manager/api/config"
    remote_config = {'remote_commands': {'localfile': {'enabled': 'no', 'exceptions': ['df -P']}}}

    # Check if the section is present in the current configuration
    assert 'remote_commands' not in check_api_config_file(), 'Remote commands were not expected in API configuration.\n ' \
                                                             f"Full configuration: {check_api_config_file()}"

    # Add the section manually
    change_api_conf(remote_config)
    assert 'remote_commands' in check_api_config_file(), f'Remote commands were expected in API configuration.\n ' \
                                                         f"Full configuration: {check_api_config_file()}"

    # Restore the configuration through the endpoint and expect the `remote_commands` section
    response = requests.delete(restore_endpoint, headers=api_details['auth_headers'], verify=False)
    assert response.status_code == 200, f'Expected status code 200.\nFull response: {response.json()}'

    assert 'remote_commands' in check_api_config_file(), f'Remote commands were deleted with endpoint.\n ' \
                                                         f"Full configuration: {check_api_config_file()}"
