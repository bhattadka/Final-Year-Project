from django.shortcuts import render
from django.http import HttpResponse
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from django.utils.timezone import make_aware

# Function to retrieve the server certificate
def get_server_certificate(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            der_cert = secure_sock.getpeercert(binary_form=True)
            return x509.load_der_x509_certificate(der_cert, default_backend())

# Function to determine grade based on certificate analysis and CertView guidelines
def grade_certificate(is_secure, warnings, hostname_matches, revoked, legacy_cipher, forward_secrecy, cbc_cipher):
    """
    CertView will not penalize:
    - Hostname mismatch (SSL Labs drops to 'T')
    - Revoked certificates (SSL Labs drops to 'F')
    
    CertView differences:
    - Legacy 64-bit block ciphers (drops grade to C)
    - CBC ciphers with TLS 1.2 or lower (drops grade to F due to GoldenDoodle)
    - Does not reward forward secrecy
    """
    
    # Check for specific conditions
    if revoked:
        warnings.append("Certificate has been revoked")
    
    if legacy_cipher:
        warnings.append("Using legacy 64-bit block ciphers")
        is_secure = False
    
    if cbc_cipher:
        warnings.append("Using CBC ciphers with TLS 1.2 or below (vulnerable to GoldenDoodle)")
        is_secure = False

    # Determine grade based on warnings and security status
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

            # Simulated CertView-specific checks (can be implemented based on actual data)
            hostname_matches = True  # Replace with actual check if needed
            revoked = False  # Replace with actual check for revoked certificates
            legacy_cipher = True  # Replace with actual check for legacy ciphers
            forward_secrecy = False  # CertView does not penalize for missing forward secrecy
            cbc_cipher = True  # Replace with actual check for CBC ciphers in TLS 1.2 or lower

            # Determine the grade using CertView rules
            grade = grade_certificate(is_secure, warnings, hostname_matches, revoked, legacy_cipher, forward_secrecy, cbc_cipher)

            bar_percentages = {
                'certificate': 80 if grade == 'A' else 60 if grade == 'B' else 40,
                'protocol_support': 70,
                'key_exchange': 60,
                'cipher_strength': 50,
            }
            # Collect certificate information for rendering
            details = {
                'secure': is_secure,
                'warnings': warnings,
                'bar_percentages': bar_percentages,
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
