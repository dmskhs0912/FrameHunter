# ---------------------------------------------------
# framehunter/stack_analyzer.py
#
# 
# ---------------------------------------------------

from .disassembler import Disassembler
from .elf_parser import ELFParser

class StackAnalyzer:
    def __init__(self, elf_file_path: str):
        self.elf_parser = ELFParser(elf_file_path)
        self.disassembler = Disassembler()
        self.functions = self.elf_parser.get_function_symbols() # 딕셔너리 형태로 함수 이름과 시작 주소, 끝 주소를 저장
        self.machine_codes = self.disassembler.disassemble_code(self.elf_parser.get_section_data('.text'), 
                                                                self.elf_parser.get_section_offset('.text')) # 기계어 코드를 저장
        self.functions_boundaries = self.disassembler.find_function_boundaries() # 함수의 시작 주소와 끝 주소를 저장


    def analyze_function_stack(self, function_name: str):
        """
        
        """
        pass

    def _get_machine_code(self, start_address: int, size: int) -> bytes:
        # ELF 파일에서 기계어 코드를 읽어오는 로직을 구현
        # 예시로 빈 바이트 배열을 반환
        return b'\x90' * size

    def _analyze_stack(self, instructions: list) -> dict:
        stack_structure = {}
        # 스택 구조 분석 로직을 구현
        # 예시로 빈 딕셔너리를 반환
        return stack_structure