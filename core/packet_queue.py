"""
packet_queue.py
----------------
A thin wrapper around Python's built-in, thread-safe queue.Queue.

Analogy: this is the conveyor belt between the loading dock (capture)
and the tally clerk (aggregator/database writer). Two different
threads touch this at the same time - one puts packets on, one takes
them off - and queue.Queue is specifically designed to make that safe
without you having to manage locks yourself.

maxsize is set so that if processing ever falls behind capture, we
stop accepting new packets rather than eating unlimited memory - the
belt has a maximum length, and if it's full, the loading dock waits.
"""

import queue


class PacketQueue:
    def __init__(self, maxsize: int = 10000):
        self._queue = queue.Queue(maxsize=maxsize)

    def put(self, record: dict):
        """Called by the capture engine. Blocks briefly if the belt is full."""
        try:
            self._queue.put(record, timeout=1)
        except queue.Full:
            # Belt is jammed - for Phase 1 we just drop the packet rather
            # than crash. A real system might log this as a "capture lag" event.
            pass

    def get(self, timeout: float = 1.0):
        """Called by the processing thread. Returns None if nothing arrived in time."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self):
        return self._queue.qsize()
