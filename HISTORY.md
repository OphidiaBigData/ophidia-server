
## v0.10.3 - 2016-07-26

### Fixed:

- Some warnings when building
- Bug in building function 'oph_if_impl' when MathEval library is disabled

### Added:

- Add compact output format for JSON Responses associated with workflows and massive operations
- Add task type OPH_STATUS_UNSELECTED for unselected branches of selection statement

### Changed:

- Change status of skipped tasks to OPH_STATUS_SKIPPED in case of errors

## v0.10.2 - 2016-07-19

### Fixed:

- Bug in handling filter 'path' in massive operations
- Bug in massive operation handler
- Several warnings when building

### Added:

- Code coverage check
- Support for data type 'string' in multigrids of JSON Responses
- Unit tests
- Support for selection statement

### Changed:

- Code indentation style
- Library 'known operators' to improve modularity

## v0.10.1 - 2016-06-27

### Fixed:

- Version number in files

## v0.10.0 - 2016-06-23

### Fixed:

- Bug in OPH_FOR parsing
- Warning 'unset variable' in oph_ssh_submit.c
- Bug in function for massive operation checking
- Bug in file matching during directory scanning
- Bug in handling subset strings for argument 'counter' of OPH_FOR
- Bug in handling on_exit:oph_delete in case of massive operations
- Bug [\#4](https://github.com/OphidiaBigData/ophidia-server/issues/4)
- Bug [\#2](https://github.com/OphidiaBigData/ophidia-server/issues/2)
- Bug [\#1](https://github.com/OphidiaBigData/ophidia-server/issues/1)

### Added:

- Support for pre-defined workflow variables
- Support for hostname in IP_TARGET_HOST configuration parameter
- Support for building on CentOS7 and Ubuntu
- Handling of DT_UNKNOWN in parsing directories for import massive operations
- Support for SHA-coded passwords

### Changed:

- Improved oph_for and oph_set to handle vectors as symbolic references

## v0.9.0 - 2016-02-01

- Initial public release
