import asyncio
import sys
from dataclasses import dataclass
import logging
import socket
from multiprocessing import Queue, Process, Value
from typing import Any
from config import Config
import socketserver

@dataclass
class Worker:
    cfg: Config
    queue: Queue
    conn_counter: Value
    handler_cls: Any
    proc: Process = None

    async def handle_connection(self, i):
        sock, addr = i
        try:
            reader, writer = await asyncio.open_connection(sock=sock)
            self.conn_counter.value += 1
            await self.handle_func(reader, writer, addr, self.cfg)
        except KeyboardInterrupt:
            logging.debug('KeyboardInterrupt')
        except Exception as e:
            logging.error(e)
        except BaseException as e:
            logging.exception(e)
        finally:
            self.conn_counter.value -= 1
            writer.close()
            await writer.wait_closed()

    async def _serve(self):
        while True:
            item = await asyncio.to_thread(self.queue.get)
            if item == 'stop':
                break
            asyncio.create_task(self.handle_connection(item))

    def start(self):
        logging.basicConfig(format='%(asctime)s - %(name)s - %(processName)s - %(funcName)s - %(levelname)s: %(message)s',
                            stream=sys.stdout,
                            datefmt="%Y-%m-%d %H:%M:%S",
                            level=logging.DEBUG)
        logging.info(f'start')
        try:
            asyncio.run(self._serve())
        except KeyboardInterrupt:
            logging.debug('KeyboardInterrupt')
        except Exception as e:
            logging.error(e)
        except BaseException as e:
            logging.exception(e)
        finally:
            self.queue.close()
        logging.info('stop')

    def consume(self, conn: (socket.socket, Any)):
        self.queue.put(conn, False)

    def __gt__(self, other):
        return self.conn_counter.value > other

    def __lt__(self, other):
        return self.conn_counter.value < other


async def watcher(workers: list, main_task: asyncio.Task):
    log = logging.getLogger('watcher')
    try:
        while True:
            print(workers)
            for w in workers:
                p = w.proc
                if p and not p.is_alive():
                    main_task.cancel(msg=f'{p.name} is dead exitcode={p.exitcode}')

            await asyncio.sleep(1)
    except BaseException as e:
        log.exception(e)


class Server:
    cfg: Config
    workers: list[Worker]
    s: socket.socket

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.server_close()

    def __init__(self, cfg: Config, handle_func):

        for i in range(cfg.worker_processes):
            w = Worker(queue=Queue(), conn_counter=Value('i', lock=False), handle_func=handle_func, cfg=cfg)
            w.proc = Process(target=w.start, name=f'worker{i}')
            w.proc.start()
            self.workers.append(w)
        asyncio.create_task(watcher(self.workers, asyncio.current_task()))

    def server_close(self):
        pass

    async def serve(self):
        family = socket.AF_INET6
        if not socket.has_dualstack_ipv6():
            logging.info("dualstack_ipv6 not supported on this platform")
            family = socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(('', self.cfg.port))
        s.listen()

        logging.info(f'Dispatcher started {HOST=}, {PORT=}')
        try:
            while True:
                conn = await asyncio.to_thread(s.accept)
                min(self.workers).consume(conn)
                await asyncio.sleep(0.0000001)
        except BaseException as e:
            logging.error(e)

        finally:
            s.close()
            for w in self.workers:
                if w.proc.is_alive():
                    w.queue.put('stop', False)
                    w.proc.join()

    def serve_forever(self):
        try:
            asyncio.run(self.serve())
        except KeyboardInterrupt:
            logging.debug('KeyboardInterrupt')
        except Exception as e:
            logging.error(e)
        except BaseException as e:
            logging.exception(e)

