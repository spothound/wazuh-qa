# Change Log
All notable changes to this project will be documented in this file.

## [v4.2.0]
### Added
- Add the documentation of Wazuh-QA repository [#1066](https://github.com/wazuh/wazuh-qa/pull/1066)
- Add new functionality for mocking agents [#1054](https://github.com/wazuh/wazuh-qa/pull/1054)
- Add support to `wodle` sections for ossec.conf generator tool [#1048](https://github.com/wazuh/wazuh-qa/pull/1048)
- Add new tests for Active Response [#1029](https://github.com/wazuh/wazuh-qa/pull/1029)
- Add focal feed and improve vulnerability scan tests [#1025](https://github.com/wazuh/wazuh-qa/pull/1025)
- Add new cases to test_env_variables to check some possible errors [#1014](https://github.com/wazuh/wazuh-qa/pull/1014)
- Add a test to verify no duplicate entries for vulnerability detector [#1010](https://github.com/wazuh/wazuh-qa/pull/1010)
- Add new case to test_basic_usage_changes to check wildcards [#1009](https://github.com/wazuh/wazuh-qa/pull/1009)
- Add some cases in test_ignore_valid, to check entire disk ignore [#1000](https://github.com/wazuh/wazuh-qa/pull/1000)
- Add new test case for duplicate registry entries [#998](https://github.com/wazuh/wazuh-qa/pull/998)
### Changed
- Improve the stop/start behavior of DB's related functions [#1068](https://github.com/wazuh/wazuh-qa/pull/1068)
- Update mock_vulnerability_scan fixture from vulnerability scan tests [#1058](https://github.com/wazuh/wazuh-qa/pull/1058)
- Update insert_vulnerability to meet new constrains [#1059](https://github.com/wazuh/wazuh-qa/pull/1059)
- Refactor the code to be PEP8 compliance [#1043](https://github.com/wazuh/wazuh-qa/pull/1043)
- Deprecate the ossec-init.conf [#1013](https://github.com/wazuh/wazuh-qa/pull/1013)
- Rename ossec-control in framework tests [#983](https://github.com/wazuh/wazuh-qa/pull/983)
- Change names of daemons in integration tests [#973](https://github.com/wazuh/wazuh-qa/pull/973)
- Rename all ossec-control references [#965](https://github.com/wazuh/wazuh-qa/pull/965)
### Fixed
- Fix sqlite3.OperationalError: no such table: VULNERABILITIES error [#1067](https://github.com/wazuh/wazuh-qa/pull/1067)
- Fix test_general_settings_ignore_time test [#1056](https://github.com/wazuh/wazuh-qa/pull/1056)
- Avoid problematic race-condition on VD integration tests for Windows [#1047](https://github.com/wazuh/wazuh-qa/pull/1047)
- QA Integration tests stabilization [#1002](https://github.com/wazuh/wazuh-qa/pull/1002)