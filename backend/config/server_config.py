import json
import os

# default values

port = 443
ui_path = "ui/dist"
cert_path = "/etc/ssl/private/max_web_server"
cert_file = "mkalitinenkov.ddns.net.crt"
key_file = "mkalitinenkov.ddns.net.key"


def generate_default_config(filename):
    with open(filename, "w+") as f:
        conf = dict(port=port, ui_path=ui_path,
                    cert_path=cert_path,
                    key_file=key_file,
                    cert_file=cert_file)
        json.dump(conf, f, sort_keys=True, indent=4)


class ServerConfig:
    def __init__(self, file_name='server_config.conf'):
        with open(file_name, 'r') as f:
            self.conf = dict()
            self.conf = json.load(f)

    def get_port(self):
        return self.conf.get('port', 443)

    def get_ui_path(self):
        return self.conf.get('ui_path', "ui/dist")

    def get_key(self):
        path = self.conf.get('cert_path', cert_path)
        file_name = self.conf.get('key_file', key_file)
        return os.path.join(path, file_name)

    def get_crt(self):
        path = self.conf.get('cert_path', cert_path)
        file_name = self.conf.get('cert_file', cert_file)
        return os.path.join(path, file_name)
