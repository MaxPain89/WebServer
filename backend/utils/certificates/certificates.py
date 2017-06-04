import os
from mproc import check_call

keysize = 2048

from . import certs_new

certs_new.generate_private_key()

def slug(name):
    return name.replace(" ", "_")

def openssl(*args):
    check_call(["openssl"] + list(args))


class Entity:
    def __init__(self, common_name, path="certificates",
                 alt_ips=[], alt_dns=[],):
        self.common_name = common_name
        self.ips = alt_ips
        self.dns = alt_dns
        self.path = os.path.abspath(path)
        if not os.path.exists(self.path):
            os.makedirs(self.path)
        self.slug = slug(self.common_name)
        self.ssl_config = None

    @property
    def key(self):
        return os.path.join(self.path, self.slug + ".key")

    @property
    def csr(self):
        return os.path.join(self.path, self.slug + ".csr")

    @property
    def crt(self):
        return os.path.join(self.path, self.slug + ".crt")

    @property
    def srl(self):
        return os.path.join(self.path, self.slug + ".srl")

    @property
    def public(self):
        return os.path.join(self.path, self.slug + "-public.pem")

    @property
    def private(self):
        return os.path.join(self.path, self.slug + "-private.pem")

    @property
    def config(self):
        if not self.ssl_config:
            self.ssl_config = self._generate_config(
                filename=os.path.join(self.path, "openssl.conf"),
                common_name=self.common_name, alt_ips=self.ips,
                alt_dns=self.dns)
        return self.ssl_config

    def create_key(self):
        openssl("genrsa", "-out", self.key, str(keysize))

    def _generate_config(self, filename, common_name, alt_ips=[], alt_dns=[]):
        with open(filename, mode="w") as f:
            f.write("[req]\n")
            f.write("distinguished_name = req_distinguished_name\n")
            f.write("req_extensions = v3_req\n")
            f.write("prompt = no\n")
            f.write("[req_distinguished_name]\n")
            f.write("CN = %s\n" % common_name)
            f.write("[v3_req]\n")
            f.write("basicConstraints = CA:FALSE\n")
            f.write("keyUsage = nonRepudiation, "
                    "digitalSignature, keyEncipherment\n")
            if alt_ips or alt_dns:
                f.write("subjectAltName = @alt_names\n")
                f.write("[alt_names]\n")
                if alt_ips:
                    for i in range(1, len(alt_ips) + 1):
                        f.write("IP.%s = %s\n" % (str(i), alt_ips[i - 1]))
                if alt_dns:
                    for i in range(1, len(alt_dns) + 1):
                        f.write("DNS.%s = %s\n" % (str(i), alt_dns[i - 1]))
        return filename

    def create_csr(self):
        openssl("req",
                "-new",
                "-key", self.key,
                "-out", self.csr,
                "-config", self.config)

    def sign(self, subject):
        openssl("x509",
                "-req",
                "-days", str(365),
                "-in", subject.csr,
                "-CA", self.crt,
                "-CAkey", self.key,
                "-CAserial", self.srl,
                "-CAcreateserial",
                "-out", subject.crt,
                "-extensions", "v3_req",
                "-extfile", subject.config)

    def self_sign(self):
        openssl("x509",
                "-req",
                "-days", str(365),
                "-in", self.csr,
                "-signkey", self.key,
                "-CAserial", self.srl,
                "-CAcreateserial",
                "-out", self.crt)

    def create_public_bundle(self, *args):
        paths = [e.crt for e in [self] + list(args)]
        combine(self.public, *paths)

    def create_private_bundle(self, *args):
        self.create_public_bundle(self, *args)
        combine(self.private, self.public, self.key)


def combine(out, *paths):
    with open(out, "w") as dest:
        for path in paths:
            with open(path) as src:
                dest.write(src.read())


def chain(base, *args):
    paths = [slug(arg) + ".crt" for arg in [base] + list(args)]
    combine(slug(base) + "-chain.pem", *paths)


def create_ca(*args, **kwargs):
    ca = Entity(*args, **kwargs)
    ca.create_key()
    ca.create_csr()
    ca.self_sign()
    ca.create_public_bundle()
    ca.create_private_bundle()
    return ca
