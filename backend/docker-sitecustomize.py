"""Keep sufficient native stack for Python worker threads in the musl runtime.

musl's small default thread stack can overflow in native parsers before Python
raises RecursionError (for example, nested JSON handled by an AnyIO worker).
This applies to new Python-created threads only; it does not relax recursion
or request-size limits. Eight MiB is reserved address space, not eager RSS.
"""
import threading

threading.stack_size(8 * 1024 * 1024)
