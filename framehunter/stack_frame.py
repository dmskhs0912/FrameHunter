# ---------------------------------------------------
# framehunter/stack_frame.py
#
# This module defines the StackFrame class, which represents
# the stack contents analyzed by the stack_analyzer.
# ---------------------------------------------------

from capstone import CsInsn

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

    def add_local_variable(self, offset, size, instructions:list[CsInsn]):
        """
        Adds a local variable to the stack frame.

        :param offset: The offset from RBP.
        :param size: The size of the variable in bytes.
        :param instructions: The list of instructions that access the variable.
        """
        self.local_variables['rbp-%d' % offset] = (size, instructions)

    def get_local_variable(self, offset):
        """
        Returns the size and instructions that access the variable of the local variable at the given offset.

        :param offset: The offset from RBP.
        :return: The size and instructions of the variable in bytes.
        """
        return self.local_variables.get('rbp-%d' % offset, None)
    
    
