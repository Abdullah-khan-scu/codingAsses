import csv
from collections import defaultdict
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
PROTOCOL_MAP = {
    '1': 'icmp',
    '6': 'tcp',
    '17': 'udp'
}

def load_lookup_table(file_path):
    lookup = defaultdict(list)
    try:
        with open(file_path, 'r') as file:
            for line_num, line in enumerate(file, 1):
                fields = line.strip().split()
                if len(fields) != 3:
                    logging.warning(f"Skipping invalid line {line_num}: Incorrect number of fields")
                    continue
                try:
                    dstport, protocol, tag = fields
                    port = int(dstport)
                    protocol = protocol.lower()
                    tag = tag.lower()
                    lookup[tag].append((port, protocol))
                except (ValueError, KeyError) as e:
                    logging.warning(f"Skipping invalid line: {line_num}. Error: {e}")
    except FileNotFoundError:
        logging.error(f"Lookup table file not found: {file_path}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Error reading lookup table file: {e}")
        sys.exit(1)
    
    if not lookup:
        logging.error("Lookup table is empty after processing")
        sys.exit(1)
    
    return dict(lookup)

def parse_flow_log(log_file, lookup_table):
    tag_counts = defaultdict(int)
    port_proto_counts = defaultdict(int)
    untagged_count = 0

    try:
        with open(log_file, 'r') as infile:
            for line_num, line in enumerate(infile, 1):
                fields = line.strip().split()
                if len(fields) != 14:
                    logging.warning(f"Skipping invalid line {line_num}: Incorrect number of fields")
                    continue
                
                try:
                    dst_port = int(fields[6])
                    protocol = PROTOCOL_MAP.get(fields[7], 'unknown')
                    
                    matched_tag = "Untagged"
                    for tag, combinations in lookup_table.items():
                        if (dst_port, protocol) in combinations:
                            matched_tag = tag
                            break
                    
                    if matched_tag == "Untagged":
                        untagged_count += 1
                    else:
                        tag_counts[matched_tag] += 1
                    
                    port_proto_counts[(dst_port, protocol)] += 1
                except ValueError as e:
                    logging.warning(f"Skipping invalid line {line_num}: {e}")
    except FileNotFoundError:
        logging.error(f"Flow log file not found: {log_file}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Error reading flow log file: {e}")
        sys.exit(1)

    tag_counts["Untagged"] = untagged_count
    return tag_counts, port_proto_counts

def write_output(tag_counts, port_proto_counts, output_file):
    try:
        with open(output_file, 'w') as outfile:
            outfile.write("Tag Counts:\n")
            outfile.write("Tag,Count\n")
            for tag, count in sorted(tag_counts.items()):
                outfile.write(f"{tag},{count}\n")
            
            outfile.write("\nPort/Protocol Combination Counts:\n")
            outfile.write("Port,Protocol,Count\n")
            for (port, proto), count in sorted(port_proto_counts.items()):
                outfile.write(f"{port},{proto},{count}\n")
    except IOError as e:
        logging.error(f"Error writing output file: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <lookup_table.txt> <input.txt> <output.txt>")
        sys.exit(1)

    lookup_table_file = sys.argv[1]
    flow_log_file = sys.argv[2]
    output_file = sys.argv[3]
    
    try:
        lookup_table = load_lookup_table(lookup_table_file)
        tag_counts, port_proto_counts = parse_flow_log(flow_log_file, lookup_table)
        write_output(tag_counts, port_proto_counts, output_file)
        logging.info(f"Flow log analysis has been written to {output_file}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()