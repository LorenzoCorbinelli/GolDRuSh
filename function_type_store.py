class FunctionTypeStore:
    def __init__(self) -> None:
        self.function_signatures = {}
        self.types_dimension = {}
        self.buffer_size = 16
        self.constrained_bytes: dict[str, list[list[int]]] = {}

    def save_signature(self, function_name: str, args_types: list[str]):
        self.function_signatures[function_name] = args_types

    def get_signature(self, function_name: str):
        return self.function_signatures.get(function_name, [])

    def is_pointer(self, function_name: str, index: int):
        return "*" in self.function_signatures[function_name][index]

    def set_types_dimension(self, function_name: str, args_size: list[int]):
        self.types_dimension[function_name] = args_size

    def get_type_dimension(self, function_name: str, index: int):
        return self.types_dimension[function_name][index]

    def set_buffer_size(self, size: int):
        self.buffer_size = size

    def get_buffer_size(self):
        return self.buffer_size

    def save_constrained_bytes(self, function_name: str, args: list[list[int]]):
        self.constrained_bytes[function_name] = args

    def get_constrained_bytes(self, function_name: str):
        return self.constrained_bytes[function_name]

type_store = FunctionTypeStore()
