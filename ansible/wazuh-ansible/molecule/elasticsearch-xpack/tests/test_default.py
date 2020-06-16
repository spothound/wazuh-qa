import os
import sys
import json

import testinfra.utils.ansible_runner
import pytest

sys.path.append(
                os.path.join(os.path.dirname(__file__), '../../_utils/')
                )
from test_utils import get_full_version, API_USER, API_PASSWORD  # noqa: E402

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.fixture(scope="module")
def ElasticRoleDefaults(host):
    return host.ansible(
        "include_vars",
        (
            "../../roles/elastic-stack/"
            "ansible-elasticsearch/defaults/main.yml"
        ),
    )["ansible_facts"]


def test_elasticsearch_is_installed(host, ElasticRoleDefaults):
    """Test if the elasticsearch package is installed."""
    elasticsearch = host.package("elasticsearch")
    elasticsearch_version = ElasticRoleDefaults["elastic_stack_version"]
    full_es_version = get_full_version(elasticsearch)
    assert elasticsearch.is_installed
    assert full_es_version.startswith(elasticsearch_version)


def test_elasticsearch_is_running(host):
    """Test if the services are enabled and running."""
    elasticsearch = host.service("elasticsearch")
    assert elasticsearch.is_enabled
    assert elasticsearch.is_running


def test_elasticsearch_has_xpack_config(host):
    """Test if xpack is enabled in elasticsearch config."""
    config = host.file("/etc/elasticsearch/elasticsearch.yml")
    assert config.contains("xpack.security.enabled: true")
    assert config.contains("xpack.security.transport.ssl.enabled: true")
    assert config.contains("xpack.security.http.ssl.enabled: true")


def test_elasticsearch_has_ssl(host):
    """Test if elasticsearch has SSL enabled."""
    cmd = host.run("curl -s -u %s:%s -k https://127.0.0.1:9200"
                   % (API_USER, API_PASSWORD))
    assert cmd.rc == 0
    assert len(cmd.stdout) > 0


def test_elasticsearch_response(host):
    """Test elasticsearch response contains no errors."""
    cmd = host.run("curl -s -u %s:%s -k https://127.0.0.1:9200"
                   % (API_USER, API_PASSWORD))
    assert "error" not in cmd.stdout


def test_elasticsearch_version_is_correct(host, ElasticRoleDefaults):
    """Test elasticsearch response contains no errors."""
    elasticsearch_version = ElasticRoleDefaults["elastic_stack_version"]
    cmd = host.run("curl -s -u %s:%s -k https://127.0.0.1:9200"
                   % (API_USER, API_PASSWORD))
    result = json.loads(cmd.stdout)
    assert result["version"]["number"] == elasticsearch_version


def test_elasticsearch_number_of_nodes(host):
    """Test number of elasticsearch nodes."""
    cmd = host.run("curl -s -u %s:%s -k https://127.0.0.1:9200/_nodes/"
                   % (API_USER, API_PASSWORD))
    result = json.loads(cmd.stdout)
    assert result["_nodes"]["total"] == 2
    assert result["_nodes"]["successful"] == 2
    assert result["_nodes"]["failed"] == 0


def test_elasticsearch_cluster_health(host):
    """Test elasticsearch cluster health."""
    cmd = host.run("curl -s -u %s:%s"
                   " -k https://127.0.0.1:9200/_cluster/health/"
                   % (API_USER, API_PASSWORD))
    result = json.loads(cmd.stdout)
    assert result["status"] == "green"
    assert result["number_of_nodes"] == 2
