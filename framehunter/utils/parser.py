# ---------------------------------------------------
# utils/parser.py
#
# 
# ---------------------------------------------------

import re

def parse_memory_reference(memory_ref: str):
    """
    Parse a memory reference in the form [base + index*scale + displacement] and extract the components.

    :param memory_ref: The memory reference string (e.g., '[rbp + rsi*8 - 0x20]')
    :return: A dictionary containing 'base', 'index', 'scale', and 'displacement'.
    """
    memory_ref = memory_ref.strip('[]').replace(' ', '')

    result = {
        'base': None,
        'index': None,
        'scale': 1,  
        'displacement': 0
    }

    base_pattern = r'([a-zA-Z0-9]+)'  
    index_pattern = r'([a-zA-Z0-9]+)\*(\d+)'  
    displacement_pattern = r'([+-]0x[0-9a-fA-F]+|\d+)'  

    components = re.split(r'(\+|\-)', memory_ref)

    for i, component in enumerate(components):
        component = component.strip()

        if re.match(base_pattern, component) and '*' not in component and not component.startswith(('0x', '-', '+')):
            result['base'] = component

        elif '*' in component:
            match = re.match(index_pattern, component)
            if match:
                result['index'] = match.group(1)
                result['scale'] = int(match.group(2))

        elif re.match(displacement_pattern, component):
            if component.startswith('-'):
                result['displacement'] -= int(component, 16 if '0x' in component else 10)
            else:
                result['displacement'] += int(component, 16 if '0x' in component else 10)

    return result