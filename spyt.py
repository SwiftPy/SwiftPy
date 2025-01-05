import re
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} filename.spyt")
    sys.exit(1)

# Valid file?
filename = sys.argv[-1]
try:
    with open(filename) as f:
        smp_code = f.read()
except FileNotFoundError:
    print("The specified file was not found.")
    sys.exit(2)
else:
    try:
        file_extension = filename.split('.')[-1]
        if file_extension != "spyt":
            print(f"Wrong file extension: {file_extension}")
            sys.exit(3)
    except IndexError:
        print(f"Please provide a file extension too.")
        sys.exit(4)
        

class Lexer:
    def __init__(self, code):
        self.code = code
        self.tokens = []
        self.current_token = ''
        self.keywords = {'func', 'print', 'for', 'in'}
        self.token_specification = [
            ('NUMBER', r'\d+'),  # Integer
            ('IDENT', r'[A-Za-z_]\w*'),  # Identifiers (including underscores)
            ('OP', r'[+=*]'),  # Arithmetic operators
            ('STRING', r'\".*?\"'),  # String literals
            ('LPAREN', r'\('),  # Left parenthesis
            ('RPAREN', r'\)'),  # Right parenthesis
            ('LBRACE', r'\{'),  # Left brace
            ('RBRACE', r'\}'),  # Right brace
            ('COMMA', r','),  # Comma
            ('NEWLINE', r'\n'),  # Line endings
            ('SKIP', r'[ \t]+'),  # Skip over spaces and tabs
            ('MISMATCH', r'.'),  # Any other character
        ]
        self.token_regex = '|'.join(f'(?P<{pair[0]}>{pair[1]})' for pair in self.token_specification)

    def tokenize(self):
        for mo in re.finditer(self.token_regex, self.code):
            kind = mo.lastgroup
            value = mo.group()
            if kind == 'NUMBER':
                value = int(value)
            elif kind == 'IDENT' and value in self.keywords:
                kind = value.upper()
            elif kind == 'STRING':
                value = value.strip('"')
            elif kind == 'SKIP':
                continue
            elif kind == 'MISMATCH':
                raise RuntimeError(f'Unexpected character: {value}')
            self.tokens.append((kind, value))
        return self.tokens


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
        self.ast = []
        self.parenthesis_stack = []

    def parse(self):
        while self.pos < len(self.tokens):
            token = self.tokens[self.pos]
            if token[0] == 'FUNC':
                self.pos += 1
                self.ast.append(self.parse_function())
            else:
                self.ast.append(self.parse_statement())
                self.pos += 1

        # Check for mismatched parentheses after parsing
        if self.parenthesis_stack:
            raise SyntaxError("Mismatched parentheses detected")

        return self.ast

    def parse_function(self):
        if self.pos >= len(self.tokens):
            raise IndexError("Token index out of range")

        func_name = self.tokens[self.pos][1]
        self.pos += 1  # Move past the function name

        if self.pos >= len(self.tokens) or self.tokens[self.pos][0] != 'LPAREN':
            raise SyntaxError("Expected '(' after function name")

        self.pos += 1  # Skip opening parenthesis
        params = []
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] != 'RPAREN':
            if self.tokens[self.pos][0] == 'IDENT':
                params.append(self.tokens[self.pos][1])
                self.pos += 1
                if self.pos < len(self.tokens) and self.tokens[self.pos][0] == 'COMMA':
                    self.pos += 1  # Skip commas
            else:
                raise SyntaxError("Expected identifier or ')' in parameter list")


        if self.pos >= len(self.tokens) or self.tokens[self.pos][0] != 'RPAREN':
            raise SyntaxError("Expected ')' after parameter list")

        self.pos += 1  # Skip closing parenthesis

        if self.pos >= len(self.tokens) or self.tokens[self.pos][0] != 'LBRACE':
            raise SyntaxError("Expected '{' after function header")

        self.pos += 1  # Skip opening brace
        body = []
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] != 'RBRACE':
            if self.tokens[self.pos][0] != 'NEWLINE':  # Ignore newlines
                body.append(self.tokens[self.pos])
            self.pos += 1
            if self.pos < len(self.tokens):
                if self.tokens[self.pos][0] == 'LPAREN':
                    self.parenthesis_stack.append('(')
                elif self.tokens[self.pos][0] == 'RPAREN':
                    if self.parenthesis_stack:
                        self.parenthesis_stack.pop()
                    else:
                        raise SyntaxError("Mismatched parentheses detected")

        if self.pos >= len(self.tokens) or self.tokens[self.pos][0] != 'RBRACE':
            raise SyntaxError("Expected '}' after function body")

        self.pos += 1  # Skip closing brace
        return {'type': 'func', 'name': func_name, 'params': params, 'body': body}

    def parse_statement(self):
        stmt = []
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] != 'NEWLINE':
            if self.pos < len(self.tokens):
                stmt.append(self.tokens[self.pos])
                self.pos += 1
                if self.pos < len(self.tokens):
                    if self.tokens[self.pos][0] == 'LPAREN':
                        self.parenthesis_stack.append('(')
                    elif self.tokens[self.pos][0] == 'RPAREN':
                        if self.parenthesis_stack:
                            self.parenthesis_stack.pop()
                        else:
                            raise SyntaxError("Mismatched parentheses detected")
            else:
                print(f"parse_statement: Reached end of tokens unexpectedly at pos {self.pos}")  # Debugging log
                break
        return {'type': 'stmt', 'body': stmt}


class CodeGenerator:
    def __init__(self, ast):
        self.ast = ast

    def generate_code(self):
        python_code = ""
        last_was_func = False
        for node in self.ast:
            if node['type'] == 'func':
                if python_code and not last_was_func:
                    python_code += "\n"
                python_code += self.generate_function_code(node) + "\n"
                last_was_func = True
            elif node['type'] == 'stmt':
                python_code += self.generate_statement_code(node['body']) + "\n"
                last_was_func = False
        return self.refactor_code(python_code.strip())

    def generate_function_code(self, node):
        func_code = f"def {node['name']}({', '.join(node['params'])}):\n"
        for stmt in node['body']:
            if stmt[0] != 'NEWLINE':  # Skip newlines within function bodies

                func_code += f"    {self.generate_statement_code([stmt])}\n"

        return func_code

    def generate_statement_code(self, stmt):
        stmt_code = ""
        for token in stmt:
            if len(token) < 2:
                continue  # Skip invalid tokens
            if token[0] == 'PRINT':
                stmt_code += "print"
            elif token[0] == 'STRING':
                stmt_code += f"'{token[1]}'"
            elif token[0] == 'IDENT':
                stmt_code += token[1]
            elif token[0] == 'LPAREN':
                stmt_code += "("
            elif token[0] == 'RPAREN':
                stmt_code += ")"
            elif token[0] == 'OP':
                stmt_code += f" {token[1]} "
            else:
                stmt_code += token[1] if len(token) > 1 else ''


        return stmt_code.strip()

    def refactor_code(self, code):
        lines = code.split('\n')
        refactored_lines = []
        for i, line in enumerate(lines):
            if line.strip() and (i == 0 or lines[i-1].strip()):
                refactored_lines.append(line)
            elif line.strip():
                refactored_lines.append('\n' + line)
        almost_refactored = '\n'.join(refactored_lines)
        print_ptrn  = r"print\s+\(\s+'"
        print_repl  = r"print\('"
        prnstr_ptrn = r"'\s+\)"
        prnstr_repl = r"'\)"
        refactored0 = re.sub(print_ptrn, print_repl, almost_refactored)
        refactored1 = re.sub(prnstr_ptrn, prnstr_repl, refactored0)
        refactored  = refactored1.replace(r'\(', '(').replace(r'\)', ')')
        return refactored


print("Compiling to python >=3.12 <=4.0...")
lexer = Lexer(smp_code)
tokens = lexer.tokenize()

try:
    parser = Parser(tokens)
    ast = parser.parse()

    code_generator = CodeGenerator(ast)
    python_code = code_generator.generate_code().strip()

    print(python_code)
except (SyntaxError, IndexError) as e:
    print(f"Error: {e}")
