import pytest

from wazuh_testing.tools import WAZUH_CONF, WAZUH_API_CONF
from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='module')
def restore_configurations():
    """Make a backup of the ossec.conf and api.yaml to restore them after the tests."""
    with open(WAZUH_CONF) as f:
        original_ossec = f.read()

    with open(WAZUH_API_CONF) as f:
        original_api = f.read()

    yield

    with open(WAZUH_CONF, 'w') as f:
        f.write(original_ossec)

    with open(WAZUH_API_CONF, 'w') as f:
        f.write(original_api)

    control_service('restart')
