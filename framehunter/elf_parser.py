# ---------------------------------------------------
# framehunter/elf_parser.py
#
# 
# ---------------------------------------------------

from elftools.elf.elffile import ELFFile
import os

class ELFParser:
    """
    Creation: the constructor accepts a relative file path string.
    """
    def __init__(self, binary_path:str):
        """
        Loads the target ELF file and performs basic initialization.

        :param binary_path: Path to the ELF binary file to analyze
        """
        self.binary_path = binary_path
        self.elf = None
        self._load_elf()


    def _load_elf(self):
        """Load the target ELF file"""
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f'File not found: {self.binary_path}')
        
        try:
            with open(self.binary_path, 'rb') as f:
                self.elf = ELFFile(f)
        except Exception as e:
            raise RuntimeError(f'An error occurred while loading the ELF file: {e}')


    
    def get_sections(self) -> list:
        """
        Return all sections in the ELF file.

        :return: A list of elf sections.
        """
        return [section for section in self.elf.iter_sections()]
    

    def get_section_by_name(self, name):
        """
        Returns a specific section by its name.

        :param name: The name of the section (e.g. '.text')
        :return: The corresponding section object if it exists (if not, return None)
        """
        return self.elf.get_section_by_name(name)


    def get_function_symbols(self):
        """
        Returns a dictionary of function symbols with their start and end offsets.

        :return: A dictionary with function names as keys and (start_offset, end_offset) tuples as values
        """
        functions = {}
        symtab = self.elf.get_section_by_name('.symtab')
        if symtab is not None:
            for symbol in symtab.iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC':
                    start_offset = symbol['st_value']
                    end_offset = start_offset + symbol['st_size']
                    functions[symbol.name] = (start_offset, end_offset)
        else:
            print("Warning: No symbol table found. Function symbols cannot be retrieved.")

        return functions
    
    def get_text_section(self):
        """
        Returns the .text section.

        :return: The .text section object
        """
        return self.get_section_by_name('.text')
    

    def get_section_data(self, section_name):
        """
        Returns the data of a specific section.

        :param section_name: The name of the section
        :return: The binary data of the section
        """
        section = self.get_section_by_name(section_name)
        if section is not None:
            return section.data()
        return None


