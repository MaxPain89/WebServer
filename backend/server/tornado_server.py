import os
import argparse

import tornado.ioloop
import tornado.web
import handlers.main_handler as mh
import handlers.ui_handler as uh
import config.server_config as s_config
import logging

LOG = logging.getLogger(__name__)

def make_app(config):
    return tornado.web.Application([
        mh.get_handler(),
        uh.get_handler(config)])

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Web server.')
    parser.add_argument('--config',
                        help='Path to config file')

    args = parser.parse_args()
    config = s_config.ServerConfig(args.config)

    ssl_options=dict(keyfile=config.get_key(), certfile=config.get_crt())

    http_server = tornado.httpserver.HTTPServer(
        make_app(config),
        ssl_options=ssl_options)
    http_server.listen(config.get_port())
    LOG.info("Server started on port %s", str(config.get_port()))
    tornado.ioloop.IOLoop.current().start()

