"""
SIH26106 - Module F Real Forensic Data Engine
Parses real .eml files to generate all 7 Module F tables:
 1. F_Email_Authentication.csv
 2. F_Received_Hops.csv
 3. F_Forensic_Timeline.csv
 4. F_IOCs.csv
 5. F_Graph_Nodes.csv
 6. F_Graph_Edges.csv
 7. F_Forensic_Features.csv
"""

import os
import re
import email
from email import policy
from email.parser import BytesParser
import pandas as pd

class ForensicEngine:
    def __init__(self):
        self.auth_records = []
        self.received_hops = []
        self.timeline_events = []
        self.iocs = []
        self.nodes = []
        self.edges = []
        self.features = []

    def parse_eml(self, eml_path: str, email_id: str):
        with open(eml_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            
        # 1. Header Extraction
        from_hdr = msg.get('From', '')
        to_hdr = msg.get('To', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')
        date_hdr = msg.get('Date', '')
        auth_hdr = msg.get('Authentication-Results', '')
        
        def extract_domain(addr_str: str):
            match = re.search(r'@([a-zA-Z0-9\.\-]+)', addr_str)
            return match.group(1).lower() if match else None

        from_domain = extract_domain(from_hdr)
        reply_domain = extract_domain(reply_to)
        return_domain = extract_domain(return_path)

        # 2. Authentication Parsing (PART 2)
        spf_res = re.search(r'spf=([a-z]+)', auth_hdr, re.IGNORECASE)
        dkim_res = re.search(r'dkim=([a-z]+)', auth_hdr, re.IGNORECASE)
        dmarc_res = re.search(r'dmarc=([a-z]+)', auth_hdr, re.IGNORECASE)

        self.auth_records.append({
            'email_id': email_id,
            'authentication_results': auth_hdr if auth_hdr else None,
            'spf_result': spf_res.group(1).lower() if spf_res else 'none',
            'spf_domain': from_domain,
            'dkim_result': dkim_res.group(1).lower() if dkim_res else 'none',
            'dkim_domain': from_domain,
            'dkim_selector': None,
            'dmarc_result': dmarc_res.group(1).lower() if dmarc_res else 'none',
            'dmarc_domain': from_domain,
            'received_spf': msg.get('Received-SPF', None),
            'auth_header_present': 1 if auth_hdr else 0
        })

        # 3. Received Header Parsing (PART 3) & Timeline (PART 4)
        received_list = msg.get_all('Received', [])
        unique_ips, unique_domains = set(), set()

        for idx, rec in enumerate(received_list):
            hop_num = idx + 1
            from_match = re.search(r'from\s+([^\s]+)', rec)
            by_match = re.search(r'by\s+([^\s]+)', rec)
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', rec)
            
            ip_addr = ip_match.group(1) if ip_match else None
            from_host = from_match.group(1) if from_match else None
            by_host = by_match.group(1) if by_match else None

            if ip_addr:
                unique_ips.add(ip_addr)
                self.iocs.append({
                    'ioc_id': f"IOC_IP_{email_id}_{idx+1}",
                    'email_id': email_id,
                    'ioc_type': 'IP',
                    'ioc_value': ip_addr,
                    'source': 'Received_Header',
                    'context': f"Hop {hop_num}"
                })
            if from_host:
                unique_domains.add(from_host)

            self.received_hops.append({
                'email_id': email_id,
                'hop_number': hop_num,
                'received_from': from_host,
                'received_by': by_host,
                'ip_address': ip_addr,
                'hostname': from_host,
                'timestamp': date_hdr,
                'raw_received_header': rec
            })

            self.timeline_events.append({
                'event_id': f"EVT_REC_{email_id}_{hop_num}",
                'email_id': email_id,
                'timestamp': date_hdr,
                'event_type': 'email_routed',
                'source': from_host or 'Unknown',
                'source_ip': ip_addr,
                'destination': by_host or 'Unknown',
                'description': f"MTA Transfer Hop {hop_num}"
            })

        # 4. Graph Construction (PART 7)
        email_node = f"NODE_EMAIL_{email_id}"
        self.nodes.append({'node_id': email_node, 'node_type': 'EMAIL', 'node_value': email_id, 'email_id': email_id})

        if from_hdr:
            sender_node = f"NODE_SENDER_{from_hdr}"
            self.nodes.append({'node_id': sender_node, 'node_type': 'SENDER', 'node_value': from_hdr, 'email_id': email_id})
            self.edges.append({'edge_id': f"EDGE_1_{email_id}", 'source_node': email_node, 'target_node': sender_node, 'relationship': 'sent_by', 'email_id': email_id})

        if from_domain:
            domain_node = f"NODE_DOM_{from_domain}"
            self.nodes.append({'node_id': domain_node, 'node_type': 'DOMAIN', 'node_value': from_domain, 'email_id': email_id})
            if from_hdr:
                self.edges.append({'edge_id': f"EDGE_2_{email_id}", 'source_node': sender_node, 'target_node': domain_node, 'relationship': 'uses_domain', 'email_id': email_id})

        # 5. Features Compilation (PART 10)
        self.features.append({
            'email_id': email_id,
            'received_hop_count': len(received_list),
            'unique_received_ips': len(unique_ips),
            'unique_received_domains': len(unique_domains),
            'authentication_header_present': 1 if auth_hdr else 0,
            'spf_result': self.auth_records[-1]['spf_result'],
            'dkim_result': self.auth_records[-1]['dkim_result'],
            'dmarc_result': self.auth_records[-1]['dmarc_result'],
            'reply_to_mismatch': 1 if reply_domain and from_domain and reply_domain != from_domain else 0,
            'return_path_mismatch': 1 if return_domain and from_domain and return_domain != from_domain else 0,
            'sender_domain': from_domain,
            'reply_domain': reply_domain,
            'first_received_timestamp': date_hdr,
            'last_received_timestamp': date_hdr,
            'routing_duration': None
        })

    def export_csvs(self, output_dir: str = "."):
        pd.DataFrame(self.auth_records).to_csv(os.path.join(output_dir, "F_Email_Authentication.csv"), index=False)
        pd.DataFrame(self.received_hops).to_csv(os.path.join(output_dir, "F_Received_Hops.csv"), index=False)
        pd.DataFrame(self.timeline_events).to_csv(os.path.join(output_dir, "F_Forensic_Timeline.csv"), index=False)
        pd.DataFrame(self.iocs).to_csv(os.path.join(output_dir, "F_IOCs.csv"), index=False)
        pd.DataFrame(self.nodes).to_csv(os.path.join(output_dir, "F_Graph_Nodes.csv"), index=False)
        pd.DataFrame(self.edges).to_csv(os.path.join(output_dir, "F_Graph_Edges.csv"), index=False)
        pd.DataFrame(self.features).to_csv(os.path.join(output_dir, "F_Forensic_Features.csv"), index=False)