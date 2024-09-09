import argparse
from framehunter.stack_analyzer import StackAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Analyze stack frames of a binary.')
    parser.add_argument('elf_file', type=str, help='The path to the ELF file to analyze.')
    parser.add_argument('function_name', type=str, help='The name of the function to analyze.')
    parser.add_argument('-V', '--visualize', action='store_true', help='Visualize the stack frame.')
    parser.add_argument('-f', '--function', type=str, help='Finds the offset of arguments of the given function.')

    args = parser.parse_args()

    stack_analyzer = StackAnalyzer(args.elf_file)
    stack_frame = stack_analyzer.analyze_function_stack(args.function_name)
    stack_analyzer.analyze_local_variables(stack_frame)

    if args.function:
        res = stack_analyzer.find_arguments(stack_frame, args.function)
        for i, item in enumerate(res):
            for j, offset in enumerate(item):
                res[i][j] = 'rbp - ' + hex(-offset)
                

    if args.visualize:
        pass #TODO: Implement visualization
    else:
        print(f'Stack Frame Analysis for function {args.function_name}')
        print('----------------------------------------------')
        print(f'Stack Size: {stack_frame.stack_size}')
        print(f'Return Address Offset: [rbp+{stack_frame.return_address_offset}]')
        if stack_frame.canary_offset:
            print(f'Canary Offset: {stack_frame.canary_offset}')
        print('Local Variables:')
        print(f'{"offset":<15} | {"size":<10}')  # 헤더 정렬
        print('------------------------------')
        for offset, value in stack_frame.local_variables.items():
            print(f'rbp-{hex(-offset):<11} | {value[0]:<10}')
        print('----------------------------------------------')
        if res:
            print(f'Arguments for function {args.function}:')
            print(res)

    

if __name__ == '__main__':
    main()