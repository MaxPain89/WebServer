import tornado

regular_path = r"/api/helloWorld"


def get_handler():
    return regular_path, MainHandler


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")
