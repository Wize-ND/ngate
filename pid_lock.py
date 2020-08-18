import logging
import os
import sys
import psutil


# pid lock file logic
def check_lock(filename):
    """
    check lock-file, if exist: check pid_exists, if exists does sys.exit(0), if not will create lock-file with actual pid
    :param filename: lock-file
    """
    if os.path.exists(filename):
        with open(filename, 'r') as lock_file:
            lock_pid = int(lock_file.read())
            is_running = psutil.pid_exists(lock_pid)
        if is_running:
            logging.warning('Lock-file exists and process is running')
            sys.exit(0)
    try:
        with open(filename, 'w') as lock_file:
            lock_file.write(str(os.getpid()))
    except Exception as e:
        logging.error(f'Could not create lock-file: {str(e)}')
        sys.exit(1)


def remove_lock(filename):
    """
    remove lock-file if pid = os.getpid()
    :param filename: lock-file
    """
    if os.path.exists(filename):
        with open(filename, 'r') as lock_file:
            lock_pid = int(lock_file.read())
        if os.getpid() == lock_pid:
            os.remove(filename)
