#Name: Hajra Sindhu
#ID: 041182345

import sys
import json
import yaml
import xml.etree.ElementTree as ET

def read_policy(filename):
    """Read the YAML compliance policy."""

    with open(filename, "r", encoding = "utf-8") as file:
        policy = yaml.safe_load(file)
    
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

    tree = ET.parse(filename)
    root = tree.getroot()

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

    for device in root.findall("device"):
        device_id = device.get("id")

        #skip devices without an id
        if device_id is None:
            skipped_devices += 1
            continue
        
        #couts valid devices
        total_devices +=1

        #device role
        role = device.get("role")

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

        print(device_id)
    
    #displays the result
    print("Total devices: ", total_devices)
    print("Skipped devices: ", skipped_devices)
    print("Roles: ", roles)
    print("Interfaces: ", interfaces)
    print("Violations:", violations)

#tests yaml policy 
policy = read_policy("PA2_policy.yaml")

#tests xml inventory 
read_inventory("PA2_sample1.xml", policy)