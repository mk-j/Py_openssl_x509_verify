#include <Python.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

static PyObject *
openssl_cipher_iv_length(PyObject *self, PyObject *args)
{
    const char *method;
    int method_len;
    const EVP_CIPHER *cipher_type;

    if (!PyArg_ParseTuple(args, "s", &method))
    {
        return NULL;
    }

    cipher_type = EVP_get_cipherbyname(method);
    if (!cipher_type) {
        return PyInt_FromLong(-1);
    }

    method_len = EVP_CIPHER_iv_length(cipher_type);
    return PyInt_FromLong(method_len);
}

static PyObject *
openssl_x509_verify(PyObject *self, PyObject *args)
{
    const char *pem_cert;
    const char *pem_ca;

    if (!PyArg_ParseTuple(args, "ss", &pem_cert,&pem_ca)) {
        return NULL;
    }
    if (!pem_cert || !pem_cert[0]) {
        return PyInt_FromLong(-1);
    }
    if (!pem_ca || !pem_ca[0]) {
        return PyInt_FromLong(-1);
    }

    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, pem_ca);
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
 
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, pem_cert);
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);

    int result = -1;
    if (issuer && x509)
    {
        EVP_PKEY *signing_key=X509_get_pubkey(issuer);
        result = signing_key && X509_verify(x509, signing_key);
        EVP_PKEY_free(signing_key);
    }
 
    BIO_free(b);
    BIO_free(c);
    X509_free(x509);
    X509_free(issuer);
    
    return PyInt_FromLong(result);
}


static PyMethodDef x509VerifyMethods[] = {
    {"openssl_cipher_iv_length", openssl_cipher_iv_length, METH_VARARGS, "calculate cipher iv length."},
    {"openssl_x509_verify", openssl_x509_verify, METH_VARARGS, "x509 check pem signature against issuing ca cert."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initx509tools(void)
{
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    (void) Py_InitModule("x509tools", x509VerifyMethods);
}
