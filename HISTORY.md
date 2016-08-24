
## v0.10.5 - 2016-08-24

### Fixed:

- Handler of SSH library used for task submission, locking, sessions, etc.
- Bug in setting basic notification message for massive operations (INDIGO-DataCloud Project)
- Skip 'lib' in referring to libmatheval
- Job status when OPH_START_ERROR occurs
- Operation to be executed when OPH_START_ERROR occurs in case of the final task
- Counter update of OPH_FOR when default values are used (INDIGO-DataCloud Project)
- Bug in building function 'oph_if_impl' when MathEval library is disabled (INDIGO-DataCloud Project)
- Bug in handling filter 'path' in massive operations (INDIGO-DataCloud Project)
- Bug in massive operation handler (INDIGO-DataCloud Project)
- Several warnings when building

### Added:

- Monitor of the submitted jobs
- Support for auto-retry in case of resource manager errors
- Check for return values of SSH-submitted commands
- Compact output format for JSON Responses associated with workflows and massive operations (INDIGO-DataCloud Project)
- Task type OPH_STATUS_UNSELECTED for unselected branches of selection statement (INDIGO-DataCloud Project)
- Code coverage check (INDIGO-DataCloud Project)
- Support for data type 'string' in multigrids of JSON Responses
- Unit tests (INDIGO-DataCloud Project)
- Support for selection statement (INDIGO-DataCloud Project)

### Changed:

- Status of skipped tasks to OPH_STATUS_SKIPPED in case of errors (INDIGO-DataCloud Project)
- Code indentation style (INDIGO-DataCloud Project)
- Library 'known operators' to improve modularity (INDIGO-DataCloud Project)

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
