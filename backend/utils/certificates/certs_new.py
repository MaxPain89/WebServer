from OpenSSL import crypto
import os


class SignAlg:
    SHA256 = "sha256"
    SHA1 = "sha1"


class RequestInfo:
    def __init__(self, common_name, country=None, state=None, city=None,
                 organization_name=None, organizational_unit=None,
                 email=None):
        self.common_name = common_name
        self.organization_name = organization_name
        self.organizational_unit = organizational_unit
        self.city = city
        self.state = state
        self.country = country
        self.email = email


class Entity:
    def __init__(self, days):
        self.days = days
        self.key = None
        self.scr = None
        self.crt = None

    def generate_private_key(self, size=2048, file=None, del_if_exist=True):
        """Generate private key.

        Keyword arguments:

        size -- size of private key

        file -- path to file, if the parameter is specified
        then key will be saved in file

        del_if_exist -- boolean flag for deleting file if it already exist
        """
        self.key = crypto.PKey()
        self.key.generate_key(crypto.TYPE_RSA, size)
        if file:
            pkey_binary = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.key)
            self._save_to_file(pkey_binary, file, del_if_exist)
        return self.key

    def get_public_key(self, file=None, del_if_exist=True):
        """Get public key from private

        Keyword arguments:

        p_key -- private key

        file -- path to file, if the parameter is specified
        then key will be saved in file

        del_if_exist -- boolean flag for deleting file if it already exist
        """
        pub_key_binary = crypto.dump_publickey(crypto.FILETYPE_PEM, self.key)
        if file:
            self._save_to_file(pub_key_binary, file, del_if_exist)
        return pub_key_binary.decode()

    def generate_csr(self, req_info, sign_alg=SignAlg.SHA256,
                     file=None, del_if_exist=True):
        self.scr = crypto.X509Req()
        self.scr.get_subject().commonName = req_info.common_name
        if req_info.country:
            self.scr.get_subject().countryName = req_info.country
        if req_info.state:
            self.scr.get_subject().stateOrProvinceName = req_info.state
        if req_info.city:
            self.scr.get_subject().localityName = req_info.city
        if req_info.organization_name:
            self.scr.get_subject().organizationName = req_info.organization_name
        if req_info.organizational_unit:
            self.scr.get_subject().organizationalUnitName\
                = req_info.organizational_unit
        if req_info.email:
            self.scr.get_subject().emailAddress = req_info.email
        self.scr.set_pubkey(self.key)
        self.scr.sign(self.key, sign_alg)
        if file:
            csr_bin = crypto.dump_certificate_request(crypto.FILETYPE_PEM,
                                                      self.scr)
            self._save_to_file(csr_bin, file, del_if_exist)
        return self.scr

    def generate_crt(self, ca, sign_alg=SignAlg.SHA256,
                     file=None, del_if_exist=True,
                     alt_dns=list(), alt_ips=list()):
        self.crt = crypto.X509()
        self.crt.set_subject(self.scr.get_subject())
        self.crt.gmtime_adj_notBefore(0)
        self.crt.gmtime_adj_notAfter(self.days * 24 * 60 * 60)
        # TODO figure out what is the serial mean
        self.crt.set_serial_number(78)
        self.crt.set_issuer(ca.crt.get_subject())
        self.crt.set_pubkey(self.scr.get_pubkey())
        self.crt.sign(ca.key, sign_alg)
        alt_names = list()
        for dns in alt_dns:
            alt_names.append(":".join(["DNS", dns]))
        for ip_name in alt_ips:
            alt_names.append(":".join(["IP", ip_name]))
        if alt_names:
            self.crt.add_extensions([
                crypto.X509Extension(
                    b"subjectAltName", False, ", ".join(alt_names).encode()
                )
            ],)
        if file:
            crt_bin = crypto.dump_certificate(crypto.FILETYPE_PEM, self.crt)
            self._save_to_file(crt_bin, file, del_if_exist)
        return self.crt

    def generate_self_sign_crt(self, sign_alg=SignAlg.SHA256,
                               file=None, del_if_exist=True):
        self.crt = crypto.X509()
        self.crt.set_subject(self.scr.get_subject())
        self.crt.gmtime_adj_notBefore(0)
        self.crt.gmtime_adj_notAfter(self.days * 24 * 60 * 60)
        # TODO figure out what is the serial mean
        self.crt.set_serial_number(78)
        self.crt.set_issuer(self.scr.get_subject())
        self.crt.set_pubkey(self.scr.get_pubkey())
        self.crt.sign(self.key, sign_alg)
        if file:
            crt_bin = crypto.dump_certificate(crypto.FILETYPE_PEM, self.crt)
            self._save_to_file(crt_bin, file, del_if_exist)
        return self.crt

    @staticmethod
    def _save_to_file(obj, file_name, del_if_exist=True):
        """
        Save the object *obj* into a file with name *file_name*
        If the file already exist, then delete it and create new one,
        if *del_if_exist* set to true, otherwise raise exception.

        :param obj: object for saving
        :param str file_name: file name for saving
        :param bool del_if_exist: (optional) boolean flag for deleting
            target file,
            if it already exist, or raise exception.
        """
        if os.path.isfile(file_name):
            if del_if_exist:
                os.remove(file_name)
            else:
                raise Exception("File %s already exist" % file_name)
        with open(file_name, "wb") as f:
            f.write(obj)


def create_ca(req, days=10*365, save_files=True, path=None):
    if not path:
        path = os.path.abspath("certificates")
    os.makedirs(path, exist_ok=True)
    if save_files:
        ca_key_path = os.path.join(path, req.common_name + ".key")
        ca_pub_key_path = os.path.join(path, req.common_name + "_pub.key")
        ca_csr_path = os.path.join(path, req.common_name + ".csr")
        ca_crt_path = os.path.join(path, req.common_name + ".crt")
    else:
        ca_key_path = None
        ca_pub_key_path = None
        ca_csr_path = None
        ca_crt_path = None
    ca = Entity(days)
    ca.generate_private_key(file=ca_key_path)
    ca.get_public_key(file=ca_pub_key_path)
    ca.generate_csr(req_info=req, file=ca_csr_path)
    ca.generate_self_sign_crt(file=ca_crt_path)
    return ca


def create_certificate(req, ca, days=365, save_files=True, path=None,
                       alt_dns=list(), alt_ips=list()):
    if not path:
        path = os.path.abspath("certificates")
    os.makedirs(path, exist_ok=True)
    if save_files:
        key_path = os.path.join(path, req.common_name + ".key")
        pub_key_path = os.path.join(path, req.common_name + "_pub.key")
        csr_path = os.path.join(path, req.common_name + ".csr")
        crt_path = os.path.join(path, req.common_name + ".crt")
    else:
        key_path = None
        pub_key_path = None
        csr_path = None
        crt_path = None
    cert = Entity(days)
    cert.generate_private_key(file=key_path)
    cert.get_public_key(file=pub_key_path)
    cert.generate_csr(req, file=csr_path)
    cert.generate_crt(ca, file=crt_path, alt_dns=alt_dns, alt_ips=alt_ips)
    return cert


ca_req = RequestInfo(common_name="rootCa", country="RU",
                     state="SmolObl",
                     city="Smolensk", organization_name="Max org",
                     organizational_unit="IT", email="mail@mail.com")

server_req = RequestInfo(common_name="kalitinenkov.ddns.net", country="RU",
                         state="SmolObl",
                         city="Smolensk", organization_name="Max org",
                         organizational_unit="IT",
                         email="kalitinenkov@gmail.com")

path = os.path.abspath(os.path.join("certs"))
ca = create_ca(ca_req, path=path)
cert = create_certificate(req=server_req, ca=ca, path=path,
                          alt_dns=["kalitinenkov.ddns.net"],
                          alt_ips=["172.22.8.198"])
