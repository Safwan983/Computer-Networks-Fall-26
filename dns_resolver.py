import socket
import random
import struct

print("DNS Resolver Assignment")

dns_server = input("Enter DNS Server IP: ")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

while True:
    domain = input("\nEnter domain name (or type exit to quit): ").strip()

    if domain.lower() == "exit":
        break

    if not domain:
        print("Error: Domain name cannot be empty.")
        continue

    domain = domain.rstrip(".")

    transaction_id = random.randint(0, 65535)

    flags = 0x0100

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        1,
        0,
        0,
        0
    )

    qname = b""

    try:
        for part in domain.split("."):
            if len(part) > 63:
                raise ValueError("A domain label cannot exceed 63 characters.")
            qname += bytes([len(part)])
            qname += part.encode()

        qname += b"\x00"

        question = qname + struct.pack("!HH", 1, 1)

        dns_query = header + question

    except ValueError as e:
        print("Error:", e)
        continue

    print("\nDNS query created successfully.")
    print("Transaction ID:", transaction_id)
    print("Domain:", domain)
    print("DNS Server:", dns_server)
    print("Query Type: A")
    print("Query Class: IN")
    print("Query size:", len(dns_query), "bytes")

    try:
        sock.sendto(dns_query, (dns_server, 53))

        print("\nDNS query sent successfully!")

        response, server_address = sock.recvfrom(4096)

        print("DNS response received!")
        print("Response size:", len(response), "bytes")

        if len(response) < 12:
            print("Error: DNS response is too short.")
            continue

        response_transaction_id, response_flags, question_count, answer_count, authority_count, additional_count = struct.unpack(
            "!HHHHHH", response[:12]
        )

        print("\n--- DNS Response Header ---")
        print("Transaction ID:", response_transaction_id)
        print("Transaction ID Match:", response_transaction_id == transaction_id)
        print("Flags:", hex(response_flags))
        print("Questions:", question_count)
        print("Answers:", answer_count)
        print("Authority records:", authority_count)
        print("Additional records:", additional_count)

        rcode = response_flags & 0x000F

        status_codes = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED"
        }

        status = status_codes.get(rcode, "UNKNOWN")

        print("Response Status:", status)

        if status != "NOERROR":
            print("DNS request was unsuccessful.")

        offset = 12

        while response[offset] != 0:
            length = response[offset]
            offset += 1
            offset += length

        offset += 1

        response_qtype, response_qclass = struct.unpack(
            "!HH", response[offset:offset + 4]
        )

        offset += 4

        print("\n--- DNS Question ---")
        print("Query Name:", domain)
        print("Query Type: A")
        print("Query Class: IN")

        for i in range(answer_count):
            name_length = response[offset]

            if name_length & 0xC0 == 0xC0:
                offset += 2
            else:
                while response[offset] != 0:
                    length = response[offset]
                    offset += 1
                    offset += length
                offset += 1

            record_type, record_class, ttl, data_length = struct.unpack(
                "!HHIH", response[offset:offset + 10]
            )

            offset += 10

            record_data = response[offset:offset + data_length]

            if record_type == 1 and data_length == 4:
                ip_address = socket.inet_ntoa(record_data)

                print("\n--- DNS Answer ---")
                print("Record Type: A")
                print("Record Class: IN")
                print("IP Address:", ip_address)
                print("TTL:", ttl, "seconds")
            else:
                print("\n--- DNS Answer ---")
                print("Record Type:", record_type)
                print("Record Class:", record_class)
                print("TTL:", ttl, "seconds")

            offset += data_length

    except socket.timeout:
        print("\nError: DNS server did not respond within 5 seconds.")

    except Exception as e:
        print("\nError:", e)

sock.close()

print("\nDNS Resolver closed.")