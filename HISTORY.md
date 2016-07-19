
## v0.10.2 - 2016-07-19

### Fixed:

- Bug in handling filter 'path' in massive operations
- Bug in massive operation handler
- fread errors
- A number of warnings

### Added:

- Code coverage check
- Code style
- Unit tests

### Changed:

- Improved support for selection statement
- Operators oph_for and oph_if for unit tests

## v0.10.1 - 2016-06-27

### Fixed:

- Bug in handling nested selection blocks

### Added:

- Initial support for selection statement

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
