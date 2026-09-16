class FunctionTypeStore:
    def __init__(self) -> None:
        self.function_signatures = {}
        self.types_dimension = {}

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

type_store = FunctionTypeStore()
