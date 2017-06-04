import common
from autotest_lib.client.common_lib import enum


# common enums for Job attributes
RebootBefore = enum.Enum('Never', 'If dirty', 'Always')
RebootAfter = enum.Enum('Never', 'If all tests passed', 'Always')


# common enums for profiler and job parameter types
ParameterTypes = enum.Enum('int', 'float', 'string', string_values=True)
