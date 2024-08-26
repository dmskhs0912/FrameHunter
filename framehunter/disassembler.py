# ---------------------------------------------------
# framehunter/disassembler.py
#
# 
# ---------------------------------------------------

from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64

class UnsupportedArchitectureError(Exception):
    """Custom exception for unsupported architectures."""
    pass

class Disassembler:
    def __init__(self, architecture=CS_ARCH_X86, mode=CS_MODE_64):
        """
        Initailizes the Capstone disassembler with the given archiatecture and mode.
        This version supports only x86_64 architecture.

        :param architecture: The architecture to disassemble (default: CS_ARCH_X86)
        :param mode: The mode (default: CS_MODE_64)
        """
        if architecture != CS_ARCH_X86 or mode != CS_MODE_64:
            raise UnsupportedArchitectureError(
                'Currently, only x86_64 architecture is supported.'
            )
        
        self.architecture = architecture
        self.mode = mode
        self.disassembler = Cs(self.architecture, self.mode)

    
    def disassemble_code(self, code, base_address) -> list[CsInsn]:
        """
        Disassembles the given machine code starting from the base address.

        :param code: The binary machine code to disassemble
        :param base_address: The base address where the code is loaded in memory
        :return: A list of disassembled instructions
        """
        return list(self.disassembler.disasm(code, base_address))
    

    def find_function_boundaries(self, instructions: list[CsInsn]):
        """
        Finds and returns the boundaries of functions within the disassembled instructions.

        :param instructions: A list of disassembled instructions
        :return: A list of tubples containing (start_address, end_address) for each function 
        """
        functions = []
        start_address = None
        in_function = False 
        for instr in instructions:
            if not in_function:
                if instr.mnemonic == 'push' and instr.op_str == 'rbp':
                    start_address = instr.address
                elif start_address is not None and instr.mnemonic == 'mov' and instr.op_str == 'rbp, rsp':
                    in_function = True
            
            elif in_function:
                if instr.mnemonic == 'ret':
                    end_address = instr.address
                    functions.append((start_address, end_address))
                    start_address = None
                    in_function = False
        return functions
    