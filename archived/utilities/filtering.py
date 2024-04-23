# filtering.py

import json

def filter_testssl_output(data):
    if data is None:
        return None, None

    # Define the keys to filter along with their readable names and categories
    ssl_tls_keys = {
        'SSLv2': 'SSL 2.0',
        'SSLv3': 'SSL 3.0',
        'TLS1': 'TLS 1.0',
        'TLS1_1': 'TLS 1.1',
        'TLS1_2': 'TLS 1.2',
        'TLS1_3': 'TLS 1.3',
        'FS_ciphers': 'Ciphers',
        'OCSP_stapling': 'OCSP Stapling',
        'cert_keySize': 'RSA Key Length',
        'FS_ECDHE_curves': 'Elliptic Curve',
        'HSTS_time': 'Strict-Transport-Security (HSTS)',
        'secure_renego': 'Secure Renegotiation',
        'DH_groups': 'Finite field-groep'
    }

    headers_keys = {
        'cookie_secure': 'Cookie Secure Flag',
        'cookie_httponly': 'Cookie HTTPOnly Flag',
        'X-Frame-Options': 'X-Frame-Options',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'Content-Security-Policy': 'Content-Security-Policy',
        'Referrer-Policy': 'Referrer-Policy',
    }

    # Initialize filtered objects with all keys set to "not found"
    filtered_ssl_tls = {key: "not found" for key in ssl_tls_keys.values()}
    filtered_headers = {key: "not found" for key in headers_keys.values()}

    # Filter out the desired objects and update the dictionaries with actual findings
    for item in data:
        original_key = item.get('id')
        finding = item.get('finding')
        if original_key in ssl_tls_keys:
            readable_key = ssl_tls_keys[original_key]
            filtered_ssl_tls[readable_key] = finding
        elif original_key in headers_keys:
            readable_key = headers_keys[original_key]
            filtered_headers[readable_key] = finding

    return filtered_ssl_tls, filtered_headers
