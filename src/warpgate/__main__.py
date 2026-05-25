"""Command-line entry point and interactive REPL for warpgate."""
import ast
import asyncio
import code
import concurrent.futures
import inspect
import sys
import textwrap
import threading
import types
import warnings
import multiprocessing
import platform
from asyncio import futures

# asyncio.futures._chain_future was added in Python 3.5.1; polyfill for 3.5.0.
if not hasattr(futures, "_chain_future"):
    def chain_future_35(source, dest):
        """Propagate result/exception from asyncio Future source to concurrent dest."""
        def on_done(f):
            if dest.cancelled():
                return
            try:
                exc = f.exception()
            except asyncio.CancelledError:
                dest.cancel()
                return
            if exc is not None:
                dest.set_exception(exc)
            else:
                dest.set_result(f.result())
        source.add_done_callback(on_done)
    futures._chain_future = chain_future_35

from . import __version__ as warpgatev  # noqa: E402
from aionetiface import fstr, aionetiface_setup_event_loop  # noqa: E402
from aionetiface.utility.utils import (  # noqa: E402
    SUPPORTS_INTERACT_EXITMSG, SUPPORTS_TOP_LEVEL_AWAIT, vmaj, vmin,
)


class AsyncIOInteractiveConsole(code.InteractiveConsole):
    """Interactive console; supports top-level await on all Python 3.5+.

    On 3.8+ the compiler flag PyCF_ALLOW_TOP_LEVEL_AWAIT handles everything.
    On 3.5-3.7 runsource detects await-containing input, wraps it in an
    async def, runs the coroutine on the event loop, and merges any new
    local variables back into the console namespace.
    """

    def __init__(self, locals, loop):
        super().__init__(locals)
        if SUPPORTS_TOP_LEVEL_AWAIT:
            self.compile.compiler.flags |= ast.PyCF_ALLOW_TOP_LEVEL_AWAIT

        self.loop = loop
        # Tracks the running REPL task (if any) and whether the user hit
        # Ctrl-C while it was executing. Kept as instance state rather than
        # globals so the console's lifetime bounds them.
        self.repl_future = None
        self.repl_future_interrupted = False

    def runsource(self, source, filename="<input>", symbol="single"):
        if SUPPORTS_TOP_LEVEL_AWAIT:
            return super().runsource(source, filename, symbol)
        # Python < 3.8: try normal compilation first.
        try:
            code_obj = self.compile(source, filename, symbol)
        except (OverflowError, SyntaxError, ValueError) as exc:
            if "await" not in source and "async " not in source:
                self.showsyntaxerror(filename)
                return False
            # Source has await/async — distinguish incomplete from invalid.
            err = str(exc)
            if "EOF" in err or "expected an indented block" in err:
                return True  # Need more input.
            return self.run_as_async(source, filename)
        if code_obj is None:
            return True  # Incomplete input.
        self.runcode(code_obj)
        return False

    def run_as_async(self, source, filename):
        """Wrap source in an async def, run it on the loop, merge locals back."""
        ns = "repl_ns_a7c2"
        indented = textwrap.indent(source.rstrip(), "    ")
        wrapper = (
            "async def repl_coro_a7c2({ns}):\n"
            "{body}\n"
            "    {ns}.update({{k: v for k, v in locals().items() if k != '{ns}'}})\n"
        ).format(ns=ns, body=indented)
        try:
            code_obj = compile(wrapper, filename, "exec")
        except SyntaxError:
            self.showsyntaxerror(filename)
            return False
        captured = {}
        try:
            exec(code_obj, self.locals)
        except Exception:
            self.showtraceback()
            return False
        coro_func = self.locals.pop("repl_coro_a7c2", None)
        if coro_func is None:
            return False
        future = concurrent.futures.Future()

        def callback():
            self.repl_future = None
            self.repl_future_interrupted = False
            try:
                coro = coro_func(captured)
            except BaseException as exc:
                future.set_exception(exc)
                return
            try:
                self.repl_future = self.loop.create_task(coro)
                futures._chain_future(self.repl_future, future)
            except BaseException as exc:
                future.set_exception(exc)

        self.loop.call_soon_threadsafe(callback)
        try:
            future.result()
        except SystemExit:
            raise
        except BaseException:
            if self.repl_future_interrupted:
                self.write("\nKeyboardInterrupt\n")
            else:
                self.showtraceback()
            return False
        self.locals.update(captured)
        return False

    def runcode(self, code):
        """Execute a code object in the asyncio event loop, supporting top-level await."""
        future = concurrent.futures.Future()

        def callback():
            """Schedule the coroutine from the compiled code on the asyncio loop."""
            self.repl_future = None
            self.repl_future_interrupted = False

            func = types.FunctionType(code, self.locals)
            try:
                coro = func()
            except SystemExit:
                raise
            except KeyboardInterrupt as ex:
                self.repl_future_interrupted = True
                future.set_exception(ex)
                return
            except BaseException as ex:
                future.set_exception(ex)
                return

            if not inspect.iscoroutine(coro):
                future.set_result(coro)
                return

            try:
                self.repl_future = self.loop.create_task(coro)

                def propagate(task):
                    """Mirror the task's outcome onto the console's futures-Future result."""
                    if task.cancelled():
                        future.cancel()
                    elif task.exception() is not None:
                        future.set_exception(task.exception())
                    else:
                        future.set_result(task.result())

                self.repl_future.add_done_callback(propagate)
            except BaseException as exc:
                future.set_exception(exc)

        self.loop.call_soon_threadsafe(callback)

        try:
            return future.result()
        except SystemExit:
            raise
        except BaseException:
            if self.repl_future_interrupted:
                self.write("\nKeyboardInterrupt\n")
            else:
                self.showtraceback()


class REPLThread(threading.Thread):
    """Background thread that drives the asyncio REPL console interaction."""

    def run(self):
        """Drive the interactive REPL console until the user exits."""
        try:
            # Show the actual policy class name -- previously this mapped
            # to a friendly "selector" / "proactor" label, but that
            # collapsed CustomEventLoopPolicy and asyncio.DefaultEventLoopPolicy
            # to the same string, making it impossible to tell from the
            # banner whether aionetiface_setup_event_loop() had actually
            # run.  type(policy).__name__ is unambiguous.
            loop_policy = type(asyncio.get_event_loop_policy()).__name__

            spawn_method = multiprocessing.get_start_method()
            vmaj, vmin, _ = platform.python_version_tuple()
            banner = (
                fstr(
                    "Warpgate {0} REPL on Python {1}.{2} / {3}",
                    (
                        warpgatev,
                        vmaj,
                        vmin,
                        sys.platform,
                    ),
                ),
                fstr(
                    "Loop = {0}, Process = {1}",
                    (
                        loop_policy,
                        spawn_method,
                    ),
                ),
                'Use "await" directly instead of "asyncio.run()".',
                fstr("{0}from warpgate import *", (getattr(sys, "ps1", ">>> "),)),
            )

            console.push("from warpgate.do_imports import *")
            interact_kwargs = {"banner": "\n".join(banner)}
            if SUPPORTS_INTERACT_EXITMSG:
                interact_kwargs["exitmsg"] = "exiting asyncio REPL..."
            console.interact(**interact_kwargs)

        finally:
            warnings.filterwarnings(
                "ignore",
                message=r"^coroutine .* was never awaited$",
                category=RuntimeWarning,
            )

            loop.call_soon_threadsafe(loop.stop)


if __name__ == "__main__":
    # Install CustomEventLoopPolicy BEFORE touching the loop. Without this, on
    # Python 3.8+ Windows the default WindowsProactorEventLoopPolicy is still
    # active and get_event_loop() returns a ProactorEventLoop -- which the rest
    # of the stack is not built for (see aionetiface entrypoint.py).
    aionetiface_setup_event_loop()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    repl_locals = {"asyncio": asyncio}
    for key in {
        "__name__",
        "__package__",
        "__loader__",
        "__spec__",
        "__builtins__",
        "__file__",
    }:
        repl_locals[key] = locals()[key]

    console = AsyncIOInteractiveConsole(repl_locals, loop)

    try:
        import readline
        readline.get_history_length()  # activate readline support (side effect of import)
    except (ImportError, AttributeError):
        pass

    repl_thread = REPLThread()
    repl_thread.daemon = True
    repl_thread.start()

    while True:
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            if console.repl_future and not console.repl_future.done():
                console.repl_future.cancel()
                console.repl_future_interrupted = True
            continue
        else:
            break

    # ---- Clean shutdown ----
    # Cancel every pending task so sockets / transports are closed properly
    # and Python doesn't emit "Task was destroyed but it is pending!" or
    # "unclosed socket" ResourceWarnings.
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.6
        pending = asyncio.Task.all_tasks(loop)

    for task in pending:
        task.cancel()

    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

    try:
        if hasattr(loop, "shutdown_asyncgens"):
            loop.run_until_complete(loop.shutdown_asyncgens())
        if hasattr(loop, "shutdown_default_executor"):
            loop.run_until_complete(loop.shutdown_default_executor())
    finally:
        loop.close()
