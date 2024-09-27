import ipaddress


def check_ip_type(ip):
    try:
        # Create an IP address object
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a private IP
        if ip_obj.is_private:
            return "Private"
        else:
            return "Public"
    except ValueError:
        return "Invalid IP address"
    


def check_ip_version(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return "IPv4"
        elif ip_obj.version == 6:
            return "IPv6"
    except ValueError:
        return "Invalid IP address"