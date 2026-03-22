from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Generator
import numpy as np
import pandas as pd
import random
import time

from .format_fortigate import format_fortigate
from .format_paloalto import format_paloalto_csv

# Generate a timestamp for a flow, spaced ~0.3-1.5s apart.
def generate_flow_timestamp(base: datetime, flow_id: int) -> datetime:
    avg_gap_sec = random.uniform(0.3, 1.5)
    offset = timedelta(seconds=flow_id * avg_gap_sec)
    return base + offset

def stream_logs(df: pd.DataFrame, *, max_flows: int | None = None, speed: float = 1.0,
        start_time: datetime | None = None, sample_frac: float | None = None, shuffle: bool = True,
        fmt: str = "fortigate", seed: int | None = None) -> Generator[str, None, None]:
    
    if seed is not None:
        random.seed(seed)
        np.random.seed(seed)

    if sample_frac is not None:
        df = df.sample(frac=sample_frac, random_state=seed or 42)

    if shuffle:
        df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    if max_flows is not None:
        df = df.head(max_flows)

    if start_time is None:
        start_time = datetime.now(tz=timezone.utc)

    formatter = format_fortigate if fmt == "fortigate" else format_paloalto_csv
    wall_anchor = time.monotonic()

    for flow_id, (_, row) in enumerate(df.iterrows()):
        ts = generate_flow_timestamp(start_time, flow_id)
        line = formatter(row, ts, flow_id)

        # Real-time pacing
        if speed > 0:
            sim_elapsed = (ts - start_time).total_seconds()
            target_wall = wall_anchor + sim_elapsed / speed
            sleep_dur = target_wall - time.monotonic()
            if sleep_dur > 0:
                time.sleep(sleep_dur)

        yield line
