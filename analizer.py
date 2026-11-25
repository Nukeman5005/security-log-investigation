def add_one(counts, key):
    if key in counts:
        counts[key] = counts[key] + 1
    else:
        counts[key] = 1


def most_frequent(counts):
    result = []
    for i in range(5):
        top_name = ""
        top_count = 0
        for name in counts:
            if counts[name] > top_count:
                top_name = name
                top_count = counts[name]
        if top_name == "":
            break
        result.append((top_name, top_count))
        del counts[top_name]
    return result


def analyse_fire(filename):
    allowed = 0
    blocked = 0
    bad_lines = 0
    all_ips = {}
    blocked_ips = {}
    ports = {}

    try:
        file = open(filename)
    except FileNotFoundError:
        print("Could not find", filename)
        return None

    for line in file:
        parts = line.split()

        if len(parts) != 8:
            bad_lines = bad_lines + 1
            continue

        time = parts[1]
        action = parts[2]
        src = parts[3].replace("src=", "")
        dst = parts[4].replace("dst=", "")
        port = parts[6].replace("port=", "")

        if time.count(":") != 2:
            bad_lines = bad_lines + 1
            continue
        if action != "ALLOWED" and action != "BLOCKED":
            bad_lines = bad_lines + 1
            continue
        if src.count(".") != 3 or dst.count(".") != 3:
            bad_lines = bad_lines + 1
            continue
        if not port.isdigit():
            bad_lines = bad_lines + 1
            continue

        add_one(all_ips, src)
        if action == "ALLOWED":
            allowed = allowed + 1
        else:
            blocked = blocked + 1
            add_one(blocked_ips, src)
            add_one(ports, port)

    file.close()

    results = {}
    results["valid"] = allowed + blocked
    results["bad_lines"] = bad_lines
    results["allowed"] = allowed
    results["blocked"] = blocked
    results["unique_ips"] = len(all_ips)
    results["top_ips"] = most_frequent(blocked_ips)
    results["top_ports"] = most_frequent(ports)
    return results


def analyse_auth(filename):
    success = 0
    failed = 0
    locked = 0
    bad_lines = 0
    failed_ips = {}
    users = {}

    try:
        file = open(filename)
    except FileNotFoundError:
        print("Could not find", filename)
        return None

    for line in file:
        parts = line.split()

        if len(parts) != 7:
            bad_lines = bad_lines + 1
            continue

        time = parts[1]
        event = parts[2]
        user = parts[3].replace("user=", "")
        src = parts[4].replace("src=", "")

        if time.count(":") != 2:
            bad_lines = bad_lines + 1
            continue
        if user == "" or src.count(".") != 3:
            bad_lines = bad_lines + 1
            continue

        if event == "LOGIN_SUCCESS":
            success = success + 1
        elif event == "LOGIN_FAILED":
            failed = failed + 1
            add_one(failed_ips, src)
            add_one(users, user)
        elif event == "ACCOUNT_LOCKED":
            locked = locked + 1
        elif event == "LOGOUT":
            pass
        else:
            bad_lines = bad_lines + 1

    file.close()

    results = {}
    results["success"] = success
    results["failed"] = failed
    results["locked"] = locked
    results["bad_lines"] = bad_lines
    results["top_ips"] = most_frequent(failed_ips)
    results["top_users"] = most_frequent(users)
    return results


def load_suspicious(filename):
    ips = []
    try:
        file = open(filename)
        for line in file:
            ip = line.strip()
            if ip != "":
                ips.append(ip)
        file.close()
    except FileNotFoundError:
        print("Could not find", filename)
    return ips


def make_findings(fw, auth, suspicious):
    findings = []

    top_ip = fw["top_ips"][0][0]
    top_count = fw["top_ips"][0][1]
    top_port = fw["top_ports"][0][0]
    text = "Finding 1: " + top_ip + " was blocked " + str(top_count) + " times by the firewall. "
    text = text + "Port " + top_port + " was the most targeted port. "
    if top_port == "22":
        text = text + "Port 22 is SSH, possibly is probing."
    findings.append(text)

    bad_ip = auth["top_ips"][0][0]
    bad_count = auth["top_ips"][0][1]
    bad_user = auth["top_users"][0][0]
    text = "Finding 2: " + bad_ip + " had " + str(bad_count) + " failed logins. "
    text = text + "The most targeted account was " + bad_user + ". "
    text = text + str(auth["locked"]) + " account lockouts ocured. "
    text = text + "Many failures against admin accounts ."
    findings.append(text)

    for fw_item in fw["top_ips"]:
        for auth_item in auth["top_ips"]:
            if fw_item[0] == auth_item[0]:
                text = "Finding 3: " + fw_item[0] + " appears in both logs (" + str(fw_item[1]) + " blocked, "
                text = text + str(auth_item[1]) + " failed logins). The same address probing the firewall and trying to log in is stronger evidence than either log alone."
                findings.append(text)

    matches = []
    for item in fw["top_ips"] + auth["top_ips"]:
        if item[0] in suspicious and item[0] not in matches:
            matches.append(item[0])
    text = "Finding 4: " + str(len(matches)) + " of the top IPs are on suspicious_ips.txt: " + ", ".join(matches) + ". "
    text = text + "A list match is supporting evidence, not proof, so these should be investigated before any action is taken."
    findings.append(text)

    return findings


def save_report(fw, auth, findings, filename):
    try:
        out = open(filename, "w")
    except OSError:
        print("Could not write the report file")
        return
    out.write("SECURITY LOG INVESTIGATION REPORT\n")
    out.write("\nFIREWALL\n")
    out.write("Valid events: " + str(fw["valid"]) + "\n")
    out.write("Bad lines skipped: " + str(fw["bad_lines"]) + "\n")
    out.write("Allowed: " + str(fw["allowed"]) + "\n")
    out.write("Blocked: " + str(fw["blocked"]) + "\n")
    out.write("Unique source IPs: " + str(fw["unique_ips"]) + "\n")
    out.write("Top blocked IPs: " + str(fw["top_ips"]) + "\n")
    out.write("Top targeted ports: " + str(fw["top_ports"]) + "\n")
    out.write("\nAUTHENTICATION\n")
    out.write("Login success: " + str(auth["success"]) + "\n")
    out.write("Login failed: " + str(auth["failed"]) + "\n")
    out.write("Account locked: " + str(auth["locked"]) + "\n")
    out.write("Bad lines skipped: " + str(auth["bad_lines"]) + "\n")
    out.write("Top failed-login IPs: " + str(auth["top_ips"]) + "\n")
    out.write("Top targeted usernames: " + str(auth["top_users"]) + "\n")
    out.write("\nFINDINGS\n")
    for finding in findings:
        out.write(finding + "\n\n")
    out.close()


def main():
    fw = analyse_fire("firewall.log")
    auth = analyse_auth("authentication.log")
    suspicious = load_suspicious("suspicious_ips.txt")

    if fw is None or auth is None:
        print("Stopping because a file was missing.")
        return

    findings = make_findings(fw, auth, suspicious)
    save_report(fw, auth, findings, "report.txt")

    print("Firewall valid events:", fw["valid"], "| bad lines:", fw["bad_lines"])
    print("Auth failed logins:", auth["failed"], "| bad lines:", auth["bad_lines"])
    for finding in findings:
        print(finding)
    print("Report saved to report.txt")


main()