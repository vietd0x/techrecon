"""Base class for scan engines."""

import shutil
from abc import ABC, abstractmethod
from typing import List, Optional

from ..config import ScanConfig


class BaseEngine(ABC):
    name: str = ""
    binary: str = ""

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(
        self, target_file: str, output_file: str, config: ScanConfig
    ) -> List[str]:
        ...

    @abstractmethod
    def parse_output(self, output_file: str) -> List[dict]:
        ...

    def get_binary_path(self) -> Optional[str]:
        return shutil.which(self.binary)
