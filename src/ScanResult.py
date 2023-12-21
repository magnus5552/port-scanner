from constants import NO_PROTO


class ScanResult:
    def __init__(self, protocol, port, status, time_ms=None,
                 application_protocol=NO_PROTO):
        self.protocol = protocol
        self.port = port
        self.status = status
        self.time_ms = max(time_ms, 0) if time_ms else None
        self.application_protocol = application_protocol

    def format(self, verbose):
        result = f"{self.protocol} {self.port}"
        if not verbose:
            return result

        if self.time_ms:
            result += f" [{self.time_ms:.2f}ms]"

        result += f" [{self.application_protocol}] [{self.status}]"

        return result
