import argparse
from framehunter.stack_analyzer import StackAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Analyze stack frames of a binary.')
    parser.add_argument('elf_file', type=str, help='The path to the ELF file to analyze.')
    parser.add_argument('function_name', type=str, help='The name of the function to analyze.')
    parser.add_argument('-V', '--visualize', action='store_true', help='Visualize the stack frame.')

    args = parser.parse_args()

    stack_analyzer = StackAnalyzer(args.elf_file)
    stack_frame = stack_analyzer.analyze_function_stack(args.function_name)
    stack_analyzer.analyze_local_variables(stack_frame)

    if args.visualize:
        pass #TODO: Implement visualization
    else:
        print(f'Stack Frame Analysis for function {args.function_name}')
        print('----------------------------------------------')
        print(f'Stack Size: {stack_frame.stack_size}')
        print(f'Return Address Offset: {stack_frame.return_address_offset}')
        if stack_frame.canary_offset:
            print(f'Canary Offset: {stack_frame.canary_offset}')
        print('Local Variables:')
        print('   offset   |   size   ')
        print('----------------------')
        for offset, size in stack_frame.local_variables.items():
            print(f'   rbp-{hex(-offset)}   |   {size}   ')
        print('----------------------------------------------')

    

if __name__ == '__main__':
    main()