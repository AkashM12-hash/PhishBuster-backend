import trustme

ca = trustme.CA()
cert = ca.issue_cert("localhost", "127.0.0.1")

cert.private_key_pem.write_to_path("key.pem")
cert.cert_chain_pems[0].write_to_path("cert.pem")