# ---------------------------------------------------
# framehunter/stack_frame.py
#
# This module defines the StackFrame class, which represents
# the stack contents analyzed by the stack_analyzer.
# ---------------------------------------------------

BYTE = 1
DWORD = 4
QWORD = 8

class StackFrame:
    """
    StackFrame class represents the stack contents analyzed by the stack_analyzer.
    """
    def __init__(self, size, return_address_offset, canary_offset=None):
        """
        StackFrame constructor.

        :param size: The size of the stack frame.
        :param return_address_offset: The offset of the return address from RBP.
        :param canary_offset: The offset of the canary value in the stack frame (if used).
        """
        self.stack_size = size
        self.return_address_offset = return_address_offset
        self.canary_offset = canary_offset
        self.local_variables = {}
