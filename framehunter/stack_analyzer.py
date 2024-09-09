# ---------------------------------------------------
# framehunter/stack_analyzer.py
#
# 
# ---------------------------------------------------

from .disassembler import Disassembler
from .elf_parser import ELFParser
from .stack_frame import StackFrame
from .utils.parser import *
from .utils.logger import logger

REGISTER_MAP = {
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'r8':  'r8',  'r8d': 'r8',  'r8w': 'r8',  'r8b': 'r8',
    'r9':  'r9',  'r9d': 'r9',  'r9w': 'r9',  'r9b': 'r9'
}

REGISTER_64BIT_LIST = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


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
        return_address_offset = 8 # Return address offset from RBP
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
            return None
        
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
        :return: The offset of the canary value from RBP if found, otherwise None
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
                            return -int(next_instr.op_str.split('[')[1].split(']')[0].split('-')[1].strip(), 16)
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
        logger.debug(f'Analyzing local variables for function {stack_frame.function_name}')
        asm_code = stack_frame.asm_code
        for instr in asm_code:
            #logger.debug(f'Analyzing instruction {instr.mnemonic} {instr.op_str}')
            if instr.mnemonic == 'mov' and 'ptr [rbp - ' in instr.op_str:
                if 'byte ptr [rbp - ' in instr.op_str:
                    size = 1
                elif 'dword ptr [rbp - ' in instr.op_str:
                    size = 4
                elif 'qword ptr [rbp - ' in instr.op_str:
                    size = 8
                elif 'word ptr [rbp - ' in instr.op_str:
                    size = 2
                    
                offset = -int(instr.op_str.split('[')[1].split(']')[0].split('-')[1].strip(), 16)
                if offset == stack_frame.canary_offset:
                    continue
                stack_frame.add_local_variable(offset, size, [instr.mnemonic + ' ' + instr.op_str])
                logger.debug(f'Found local variable at offset -{hex(-offset)} with size {size} bytes.')
            
            elif instr.mnemonic == 'lea' and '[rbp-' in instr.op_str:
                pass # TODO: Implement this

    def trace_register(self, stack_frame: StackFrame, target_register, address):
        """
        Trace the register value at the given address and check if it uses a local variable in the stack frame.

        :param stack_frame: The stack frame to check
        :param target_register: The 64 bit register to trace
        :param address: The address to trace the register value. This should be the address of the instruction that uses the target register.
        :return: The offset of the local variables if found, otherwise None
        """
        # FIXME: 만약 여러 local variable이 사용되는 경우? ex) rsi에 v1 + v2 이 사용되는 경우
        # FIXME: movzx, movsx, movabs, movsxd 와 같은 경우는?

        asm_code = stack_frame.asm_code
        if target_register not in REGISTER_64BIT_LIST:
            raise ValueError('The target register must be a 64-bit register.')
        instr_index = next((i for i, instr in enumerate(asm_code) if instr.address == address), None)
        if instr_index is None:
            raise ValueError(f'Instruction not found at address {hex(address)}')

        for i in range(instr_index, -1, -1):
            instr = asm_code[i]

            if instr.mnemonic in ['mov', 'add', 'sub']: 
                dest, src = map(str.strip, instr.op_str.split(','))
                if REGISTER_MAP[dest] == target_register:
                    if 'PTR [rbp-' in src: # Local variable
                        try:
                            offset_str = src.split('[rbp-')[1].split(']')[0]
                            offset = -int(offset_str, 16)
                            return offset 
                        except (IndexError, ValueError):
                            continue

                    elif src in REGISTER_MAP:
                        target_register = REGISTER_MAP[src]
                        continue

            elif instr.mnemonic == 'lea':
                dest, src = map(str.strip, instr.op_str.split(','))
                if REGISTER_MAP[dest] == target_register:
                    if src.startswith('[') and src.endswith(']'):
                        parsed_src = parse_memory_reference(src)
                    else:
                        parsed_src = {'base': src, 'index': None, 'scale': 1, 'displacement': 0}

                    # FIXME: 좀 더 생각해 봐. 다 고쳐야 함.
                    if parsed_src['base'] == 'rbp':
                        offset = -parsed_src['displacement']
                        return offset
                    elif parsed_src['index'] == 'rbp':
                        offset = -parsed_src['displacement']
                        return offset
                    else:
                        target_register = REGISTER_MAP[parsed_src['base']]
                        continue
                    

    def find_arguments(self, stack_frame: StackFrame, callee_name):
        """
        Finds the offsets of the arguments passed to the callee function if it is a local variable in the stack frame.

        :param stack_frame: The stack frame of the caller function
        :param callee_name: The name or offset of the callee function
        :return: A list of list of offsets of the arguments passed to the callee function. The argument that is not a local varible is None.
        """
        result = []
        argument_registers = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        asm_code = stack_frame.asm_code
        if isinstance(callee_name, int):
            callee_name = hex(callee_name)

        if not isinstance(callee_name, str):
            raise ValueError('Callee name must be a string or an integer.')
        
        for instr in asm_code:
            if instr.mnemonic == 'call' and callee_name in instr.op_str:
                arguments = []
                for reg in argument_registers:
                    offset = self.trace_register(stack_frame, reg, instr.address)
                    arguments.append(offset)
                result.append(arguments)
        return result