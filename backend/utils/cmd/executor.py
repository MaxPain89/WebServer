
from subprocess import *
import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


def exec_cmd(*args):
    try:
        check_call(args)
    except CalledProcessError as e:
        log.error("Process exit with error code %d" % e.returncode)
