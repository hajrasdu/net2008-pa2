#Name: Hajra Sindhu
#ID: 041182345

import sys
import json
import yaml
import xml.etree.ElementTree as ET

class AuditError(Exception):
    """Represent an error while reading audit input files."""
    pass

class Device:
    """Represent a network device from the XML inventory."""

    def __init__(self, element):
        """store the device's XML element."""
        self.element = element
    
    def get_id(self):
        """return the device ID"""
        return self.element.get("id")

    def get_role(self):
        """return the device role"""
        return self.element.get("role")

def read_policy(filename):
    """Read the YAML compliance policy."""

    try:
        with open(filename, "r", encoding = "utf-8") as file:
            policy = yaml.safe_load(file)
    
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise AuditError(f"{filename}: {error}") from error
    
    #empty yaml file means no checks are enabled
    if policy is None:
        policy = {}

    #policy must be a dictionary
    if not isinstance(policy, dict):
        raise AuditError(f"{filename}: policy must be a mapping")
    
    return policy 

def compare_versions(found, required):
    """Return True if the device OS version is outdated."""

    #converts versions into lists of numbers
    found_parts = [int(part) for part in found.split(".")]
    required_parts = [int(part) for part in required.split(".")]

    #makes both lists the same length
    length = max(len(found_parts), len(required_parts))

    found_parts += [0] * (length - len(found_parts))
    required_parts += [0] * (length - len(required_parts))

    #compares the numerical versions 
    return found_parts < required_parts

def read_inventory(filename, policy):
    """Read an XML inventory and check policy violations."""

    try: 
        tree = ET.parse(filename)
        root = tree.getroot()
    except (OSError, UnicodeError, ET.ParseError) as error:
        raise AuditError(f"{filename}: {error}") from error

    #gets the site name from the xml inventory 
    site = root.get("site")

    total_devices = 0
    skipped_devices = 0
    roles = {} 

    interfaces = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    #stores all of the policy violations
    violations = []
    #stores devices that pass all policy checks
    compliant = []

    for device in root.findall("device"):
        network_device = Device(device)
        device_id = network_device.get_id()

        #skip devices without an id
        if device_id is None:
            skipped_devices += 1
            continue
        
        #couts valid devices
        total_devices +=1

        #device role
        role = network_device.get_role()

        #couts how many devices have this role
        roles[role] = roles.get(role, 0)+1

        #counts interfaces for this device
        down_count = 0

        for interface in device.findall("interface"):
            status = interface.get("status")

            if status == "up":
                interfaces["up"] += 1
            elif status == "down":
                interfaces["down"] += 1
                down_count += 1
            else:
                interfaces["other"] += 1

        #Rule 1 Check for unknown roles
        if "min_os" in policy:
            if role not in policy["min_os"]:
                violations.append({"device": device_id, "type": "unknown_role", "role": role})
            else:
                #Rule 4 Check for outdated os versions
                found = device.get("os")
                required = policy["min_os"][role]

                if compare_versions(found, required):
                    violations.append({"device": device_id, "type": "os_outdated", "found": found, "required": required})

        #Rule 2 Check for missing owners
        if policy.get("require_owner", False):
            owner = device.find("owner")

            if owner is None or not (owner.text or "").strip():
                violations.append({"device": device_id, "type": "missing_owner"})
        
        #Rule 3 Check for too mnay down interfaces
        if "max_down_interfaces" in policy:
            maximum = policy["max_down_interfaces"]

            if down_count > maximum:
                violations.append({"device": device_id, "type": "too_many_down", "down": down_count})

        #remembers how many violations exist before this device 
        violations_before = len(violations)

        if len(violations) == violations_before:
            compliant.append(device_id)

        print(device_id)
    
    #sorts compliant device ids alphabetically
    compliant.sort()

    #creates an audit report 
    report = {
        "site": site,
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": compliant
    }

    #writes an audit report to a json file
    with open("audit.json", "w", encoding = "utf-8") as file:
        json.dump(report, file, indent = 4)

    print("Audit report saved to audit.json")

    #displays the result
    print("Total devices: ", total_devices)
    print("Skipped devices: ", skipped_devices)
    print("Roles: ", roles)
    print("Interfaces: ", interfaces)
    print("Violations:", violations)

def main():
    """Check arguments, run the audit and return an exit code."""

    #tests yaml policy and xml inventory
    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        return 2
    
    inventory_file = sys.argv[1]
    policy_file = sys.argv[2]

    try: 
        """reads the YAML policy"""
        policy = read_policy(policy_file)

        """reads the xml invnetory and generate audit.json"""
        read_inventory(inventory_file, policy)

    except AuditError as error:
        print(f"Error: {error}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())