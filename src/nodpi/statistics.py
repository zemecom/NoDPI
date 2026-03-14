"""Statistics tracking."""

from __future__ import annotations

import time

from .contracts import IStatistics


class Statistics(IStatistics):
    """Statistics tracker for proxy server."""

    def __init__(self):
        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0
        self.errors_connections = 0
        self.traffic_in = 0
        self.traffic_out = 0
        self.last_traffic_in = 0
        self.last_traffic_out = 0
        self.speed_in = 0
        self.speed_out = 0
        self.average_speed_in = (0, 1)
        self.average_speed_out = (0, 1)
        self.last_time = None

    def increment_total_connections(self) -> None:
        self.total_connections += 1

    def increment_allowed_connections(self) -> None:
        self.allowed_connections += 1

    def increment_blocked_connections(self) -> None:
        self.blocked_connections += 1

    def increment_error_connections(self) -> None:
        self.errors_connections += 1

    def update_traffic(self, incoming: int, outgoing: int) -> None:
        self.traffic_in += incoming
        self.traffic_out += outgoing

    def update_speeds(self) -> None:
        current_time = time.time()
        if self.last_time is not None:
            time_diff = current_time - self.last_time
            if time_diff > 0:
                self.speed_in = (self.traffic_in - self.last_traffic_in) * 8 / time_diff
                self.speed_out = (self.traffic_out - self.last_traffic_out) * 8 / time_diff

                if self.speed_in > 0:
                    self.average_speed_in = (
                        self.average_speed_in[0] + self.speed_in,
                        self.average_speed_in[1] + 1,
                    )
                if self.speed_out > 0:
                    self.average_speed_out = (
                        self.average_speed_out[0] + self.speed_out,
                        self.average_speed_out[1] + 1,
                    )

        self.last_traffic_in = self.traffic_in
        self.last_traffic_out = self.traffic_out
        self.last_time = current_time

    def get_stats_display(self) -> str:
        col_width = 30

        conns_stat = f"\033[97mTotal: \033[93m{self.total_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " + f"\033[97mMiss: \033[96m{self.allowed_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " + f"\033[97mUnblock: \033[92m{self.blocked_connections}\033[0m".ljust(
            col_width
        ) + "\033[97m| " f"\033[97mErrors: \033[91m{self.errors_connections}\033[0m".ljust(
            col_width
        )

        traffic_stat = (
            f"\033[97mTotal: \033[96m{self.format_size(self.traffic_out + self.traffic_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mDL: \033[96m{self.format_size(self.traffic_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_size(self.traffic_out)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
        )

        avg_speed_in = self.average_speed_in[0] / self.average_speed_in[1]
        avg_speed_out = self.average_speed_out[0] / self.average_speed_out[1]

        speed_stat = (
            f"\033[97mDL: \033[96m{self.format_speed(self.speed_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mUL: \033[96m{self.format_speed(self.speed_out)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mAVG DL: \033[96m{self.format_speed(avg_speed_in)}\033[0m".ljust(
                col_width
            )
            + "\033[97m| "
            + f"\033[97mAVG UL: \033[96m{self.format_speed(avg_speed_out)}\033[0m".ljust(
                col_width
            )
        )

        title = "STATISTICS"
        top_border = f"\033[92m{'═' * 36} {title} {'═' * 36}\033[0m"
        line_conns = f"\033[92m   {'Conns'.ljust(8)}:\033[0m {conns_stat}\033[0m"
        line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}\033[0m"
        line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}\033[0m"
        bottom_border = f"\033[92m{'═' * (36 * 2 + len(title) + 2)}\033[0m"
        return (
            f"{top_border}\n{line_conns}\n{line_traffic}\n{line_speed}\n{bottom_border}"
        )

    @staticmethod
    def format_size(size: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        unit = 0
        size_float = float(size)
        while size_float >= 1024 and unit < len(units) - 1:
            size_float /= 1024
            unit += 1
        return f"{size_float:.1f} {units[unit]}"

    @staticmethod
    def format_speed(speed_bps: float) -> str:
        if speed_bps <= 0:
            return "0 b/s"

        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"
