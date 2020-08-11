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
            is_running = psutil.pid_exists(int(lock_file.read()))
        if is_running:
            logging.warning('oragate is already running')
            sys.exit(0)
    else:
        try:
            with open(filename, 'w') as lock_file:
                lock_file.write(str(os.getpid()))
                lock_created = True
        except Exception as e:
            logging.error(f'Could not create lock-file: {str(e)}')
            sys.exit(0)
    return lock_created
