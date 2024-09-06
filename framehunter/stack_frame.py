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
    def __init__(self, function_name, size, return_address_offset, canary_offset=None):
        """
        StackFrame constructor.

        :param function_name: The name or offset of the function.
        :param size: The size of the stack frame.
        :param return_address_offset: The offset of the return address from RBP.
        :param canary_offset: The offset of the canary value in the stack frame (if used).
        """
        self._function_name = function_name
        self._stack_size = size
        self._return_address_offset = return_address_offset
        self._canary_offset = canary_offset
        self._local_variables = {}
        self._asm_code = None
    
    @property
    def function_name(self):
        return self._function_name
    
    @property
    def stack_size(self):
        return self._stack_size
    
    @property
    def return_address_offset(self):
        return self._return_address_offset
    
    @property
    def canary_offset(self):
        return self._canary_offset
    
    @property
    def local_variables(self):
        return self._local_variables
    
    @property
    def asm_code(self):
        return self._asm_code
    
    @asm_code.setter
    def asm_code(self, instructions:list[CsInsn]):
        self._asm_code = instructions


    def add_local_variable(self, offset, size, instructions:list[CsInsn]):
        """
        Adds a local variable to the stack frame.

        :param offset: The offset from RBP.
        :param size: The size of the variable in bytes.
        :param instructions: The list of instructions that access the variable.
        """
        if offset in self._local_variables:
            instrs = self._local_variables[offset][1]
        else :
            instrs = []
        self._local_variables[offset] = (size, instrs + instructions) 

    def get_local_variable(self, offset):
        """
        Returns the size and instructions that access the variable of the local variable at the given offset.

        :param offset: The offset from RBP.
        :return: The size and instructions of the variable in bytes.
        """
        return self.local_variables.get(offset, None)
    
    
