class FunctionTypeStore:
    def __init__(self) -> None:
        self.function_signatures = {}

    def save_signature(self, function_name: str, args_types: list[str]):
        self.function_signatures[function_name] = args_types

    def get_signature(self, function_name: str):
        return self.function_signatures.get(function_name, [])

    def is_pointer(self, function_name: str, index: int):
        return "*" in self.function_signatures[function_name][index]

type_store = FunctionTypeStore()
