from __future__ import annotations


class ConsoleTable:
    """In bảng đơn giản trong terminal."""

    def __init__(self, title: str, columns: list[tuple[str, int]]) -> None:
        self.title = title
        self.columns = columns
        self.width = sum(width for _, width in columns) + (len(columns) - 1) * 2

    def start(self) -> None:
        print("")
        print("=" * self.width)
        print(self.title)
        print("=" * self.width)
        print(self.row([name for name, _ in self.columns]))
        print("-" * self.width)

    def print_row(self, values: list[object]) -> None:
        print(self.row(values), flush=True)

    def finish(self) -> None:
        print("-" * self.width)

    def row(self, values: list[object]) -> str:
        cells = []
        for value, (_, width) in zip(values, self.columns):
            cells.append(self.short(value, width).ljust(width))
        return "  ".join(cells)

    def short(self, value: object, width: int) -> str:
        text = str(value).replace("\n", " ").replace("\r", " ")
        return text if len(text) <= width else text[: max(0, width - 3)] + "..."
