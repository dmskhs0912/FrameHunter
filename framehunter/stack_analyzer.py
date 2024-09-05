# ---------------------------------------------------
# framehunter/stack_analyzer.py
#
# 
# ---------------------------------------------------

from .disassembler import Disassembler
from .elf_parser import ELFParser
from .stack_frame import StackFrame

class StackAnalyzer:
    def __init__(self, elf_file_path: str):
        self.elf_parser = ELFParser(elf_file_path)
        self.disassembler = Disassembler()
        self.functions = self.elf_parser.get_function_symbols() # 딕셔너리 형태로 함수 이름과 시작 주소, 끝 주소를 저장
        self.asm_codes = self.disassembler.disassemble_code(self.elf_parser.get_section_data('.text'), 
                                                                self.elf_parser.get_section_offset('.text')) # 어셈블리 코드를 저장
        #self.functions_boundaries = self.disassembler.find_function_boundaries() # 함수의 시작 주소와 끝 주소를 저장


    def analyze_function_stack(self, function_name) -> StackFrame:
        """
        Returns the stack frame of the given function.

        :param function_name: The name or offset of the function to analyze
        """
        stack_size = self._get_stack_size(function_name)
        return_address_offset = stack_size + 8 # Return address offset from RSP
        canary_offset = self._get_canary_offset(function_name)
        stack_frame = StackFrame(function_name, stack_size, return_address_offset, canary_offset)
        
        if isinstance(function_name, str):
            if function_name in self.functions:
                start_address, end_address = self.functions[function_name]
            else:
                raise ValueError(f'Function {function_name} not found.')
            function_code = [instr for instr in self.asm_codes if start_address <= instr.address < end_address]
            stack_frame.asm_code = function_code
        return stack_frame

    def _get_stack_size(self, function_name) -> int:
        """
        Returns the size of the stack frame for the given function.

        :param function_name: The name or offset of the function
        :return: The size of the stack frame in bytes
        """
        if isinstance(function_name, str): # 해당 함수의 심볼이 존재하는 경우 함수이름으로 검색
            if function_name in self.functions:
                start_address, end_address = self.functions[function_name]
            else:
                raise ValueError(f'Function {function_name} not found.')
            
            function_code = [instr for instr in self.asm_codes if start_address <= instr.address < end_address]
            for instr in function_code:
                if instr.mnemonic == 'sub' and instr.op_str.startswith('rsp, '):
                    try:
                        return int(instr.op_str.split(',')[1].strip(), 16)
                    except:
                        raise ValueError(f'Failed to find stack size for function {function_name}')
            raise ValueError(f'Failed to find stack size for function {function_name}')
        
        else:
            raise NotImplementedError('Only function names are supported for now.')
    
    def _convert_to_rbp_offset(self, rsp_offset, stack_size) -> int:
        """
        Converts the offset from RSP to the offset from RBP.

        :param rsp_offset: The offset from RSP
        :param stack_size: The size of the stack frame
        :return: The offset from RBP
        """
        return rsp_offset - stack_size

    def _convert_to_rsp_offset(self, rbp_offset, stack_size) -> int:
        """
        Converts the offset from RBP to the offset from RSP.

        :param rbp_offset: The offset from RBP
        :param stack_size: The size of the stack frame
        :return: The offset from RSP
        """
        return rbp_offset + stack_size
        
    def _get_canary_offset(self, function_name) -> int:
        """
        Returns the offset of the canary value in the stack frame for the given function.

        :param function_name: The name or offset of the function
        :return: The offset of the canary value from RSP if found, otherwise None
        """
        if isinstance(function_name, str): # 해당 함수의 심볼이 존재하는 경우 함수이름으로 검색
            if function_name in self.functions:
                start_address, end_address = self.functions[function_name]
            else:
                raise ValueError(f'Function {function_name} not found.')
            
            function_code = [instr for instr in self.asm_codes if start_address <= instr.address < end_address]
            for i, instr in enumerate(function_code):
                if instr.mnemonic == 'mov' and 'fs:0x28' in instr.op_str:
                    next_instr = function_code[i+1]
                    if next_instr.mnemonic == 'mov' and next_instr.op_str.startswith('QWORD PTR [rbp-'):
                        try:
                            rbp_offset = -int(next_instr.op_str.split('[')[1].split(']')[0].split('-')[1].strip(), 16)
                            return self._convert_to_rsp_offset(rbp_offset, self._get_stack_size(function_name))
                        except:
                            raise ValueError(f'Failed to find canary offset for function {function_name}')
            return None
        
        else:
            raise NotImplementedError('Only function names are supported for now.')
        
    def analyze_local_variables(self, stack_frame: StackFrame):
        """
        Analyzes the local variables of the given function and updates the stack frame.

        :param stack_frame: The stack frame to update
        """
        asm_code = stack_frame.asm_code
        for instr in asm_code:
            pass

                

        

        
        
