from django.shortcuts import render
from django.http import HttpResponse
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from django.utils.timezone import make_aware
from datetime import datetime, timezone

# Function to retrieve the server certificate
def get_server_certificate(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            der_cert = secure_sock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert, default_backend())

# Function to determine grade based on certificate analysis
def grade_certificate(is_secure, warnings):
    if is_secure and not warnings:
        return 'A'
    elif not is_secure and len(warnings) == 1:
        return 'B'
    elif not is_secure and len(warnings) == 2:
        return 'C'
    elif not is_secure and len(warnings) >= 3:
        return 'D'
    else:
        return 'F'

# View to analyze the SSL certificate
def analyze_certificate(request):
    if request.method == 'POST':
        hostname = request.POST.get('hostname')

        try:
            cert = get_server_certificate(hostname)
            
            is_secure = True
            warnings = []

            # Get the current time in UTC (timezone-aware)
            now = datetime.now(timezone.utc)

            # Ensure certificate times are timezone-aware
            not_valid_before = make_aware(cert.not_valid_before) if cert.not_valid_before.tzinfo is None else cert.not_valid_before
            not_valid_after = make_aware(cert.not_valid_after) if cert.not_valid_after.tzinfo is None else cert.not_valid_after

            # Check if the certificate is expired or not yet valid
            if not_valid_after < now:
                is_secure = False
                warnings.append("Certificate has expired")
            elif not_valid_before > now:
                is_secure = False
                warnings.append("Certificate is not yet valid")

            # Check key size
            public_key = cert.public_key()
            key_size = public_key.key_size
            if key_size < 2048:
                is_secure = False
                warnings.append(f"Weak key size: {key_size} bits (should be at least 2048 bits)")

            # Check signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name
            if 'sha1' in signature_algorithm.lower():
                is_secure = False
                warnings.append(f"Weak signature algorithm: {signature_algorithm}")

            # Determine the grade
            grade = grade_certificate(is_secure, warnings)

            # Collect certificate information for rendering
            details = {
                'secure': is_secure,
                'warnings': warnings,
                'hostname': hostname,
                'valid_before': not_valid_before,
                'valid_after': not_valid_after,
                'key_size': key_size,
                'signature_algorithm': signature_algorithm,
                'cert_version': cert.version,
                'serial_number': cert.serial_number,
                'issuer': cert.issuer.rfc4514_string(),
                'subject': cert.subject.rfc4514_string(),
                'grade': grade
            }

            return render(request, 'analyze.html', details)

        except ssl.SSLError as e:
            return HttpResponse(f"SSL Error: Unable to establish a secure connection to {hostname}")
        except socket.gaierror:
            return HttpResponse(f"Error: Unable to resolve hostname {hostname}")
        except socket.error as e:
            return HttpResponse(f"Connection Error: Unable to connect to {hostname}")
        except Exception as e:
            return HttpResponse(f"Unexpected error analyzing the certificate: {str(e)}")

    return render(request, 'analyze.html')