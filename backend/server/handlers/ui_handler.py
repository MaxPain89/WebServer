import tornado
import os
import config.server_config as sconfig

regular_path = r"/(.*)"
type = tornado.web.StaticFileHandler
static_path = os.path.join(os.path.dirname(sconfig.__file__), "../../..")

settings = {'path': static_path, "default_filename": "index.html"}


def get_handler(config):
    return regular_path, type, {'path': config.get_ui_path(),
                                "default_filename": "index.html"}
