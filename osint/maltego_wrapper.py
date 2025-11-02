"""
Maltego Automation Wrapper
Creates link analysis graphs and relationship mappings
"""
import json
from collections import defaultdict
import os

class MaltegoWrapper:
    def __init__(self):
        self.entities = []
        self.relationships = []
        self.graph = defaultdict(list)
        
    def add_entity(self, entity_type: str, value: str, properties: dict = None):
        """Add an entity to the graph"""
        entity = {
            'id': len(self.entities),
            'type': entity_type,
            'value': value,
            'properties': properties or {}
        }
        self.entities.append(entity)
        return entity['id']
    
    def add_relationship(self, source_id: int, target_id: int, relationship_type: str):
        """Add a relationship between entities"""
        relationship = {
            'source': source_id,
            'target': target_id,
            'type': relationship_type
        }
        self.relationships.append(relationship)
        self.graph[source_id].append(target_id)
    
    def create_person_entity(self, name: str, email: str = None, phone: str = None):
        """Create a person entity"""
        properties = {}
        if email:
            properties['email'] = email
        if phone:
            properties['phone'] = phone
        
        return self.add_entity('Person', name, properties)
    
    def create_domain_entity(self, domain: str, ip: str = None):
        """Create a domain entity"""
        properties = {}
        if ip:
            properties['ip'] = ip
        
        return self.add_entity('Domain', domain, properties)
    
    def create_email_entity(self, email: str):
        """Create an email entity"""
        return self.add_entity('Email', email)
    
    def create_ip_entity(self, ip: str, location: str = None):
        """Create an IP address entity"""
        properties = {}
        if location:
            properties['location'] = location
        
        return self.add_entity('IP Address', ip, properties)
    
    def create_phone_entity(self, phone: str, carrier: str = None):
        """Create a phone entity"""
        properties = {}
        if carrier:
            properties['carrier'] = carrier
        
        return self.add_entity('Phone', phone, properties)
    
    def create_social_media_entity(self, platform: str, username: str, url: str = None):
        """Create a social media entity"""
        properties = {'platform': platform}
        if url:
            properties['url'] = url
        
        return self.add_entity('Social Media', username, properties)
    
    def visualize_graph_ascii(self):
        """Display graph in ASCII format"""
        print("\n\033[92m" + "="*70)
        print("           LINK ANALYSIS GRAPH")
        print("="*70 + "\033[0m\n")
        
        print(f"\033[93m[*] Entities: {len(self.entities)}\033[0m")
        print(f"\033[93m[*] Relationships: {len(self.relationships)}\033[0m\n")
        
        # Display entities
        print("\033[97mEntities:\033[0m\n")
        for entity in self.entities:
            print(f"\033[92m[{entity['id']}]\033[0m {entity['type']}: \033[97m{entity['value']}\033[0m")
            if entity['properties']:
                for key, value in entity['properties'].items():
                    print(f"    {key}: {value}")
        
        # Display relationships
        print(f"\n\033[97mRelationships:\033[0m\n")
        for rel in self.relationships:
            source = self.entities[rel['source']]
            target = self.entities[rel['target']]
            print(f"\033[92m[{source['id']}]\033[0m {source['value']} --[{rel['type']}]--> \033[92m[{target['id']}]\033[0m {target['value']}")
    
    def export_to_json(self, filename: str):
        """Export graph to JSON format"""
        graph_data = {
            'entities': self.entities,
            'relationships': self.relationships
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(graph_data, f, indent=4)
            print(f"\n\033[92m[+] Graph exported to: {filename}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error exporting: {str(e)}\033[0m")
    
    def export_to_graphviz(self, filename: str):
        """Export to Graphviz DOT format"""
        try:
            with open(filename, 'w') as f:
                f.write("digraph Investigation {\n")
                f.write("  rankdir=LR;\n")
                f.write("  node [shape=box, style=rounded];\n\n")
                
                # Write nodes
                for entity in self.entities:
                    label = f"{entity['type']}\\n{entity['value']}"
                    f.write(f"  node{entity['id']} [label=\"{label}\"];\n")
                
                f.write("\n")
                
                # Write edges
                for rel in self.relationships:
                    f.write(f"  node{rel['source']} -> node{rel['target']} [label=\"{rel['type']}\"];\n")
                
                f.write("}\n")
            
            print(f"\n\033[92m[+] Graphviz file exported to: {filename}\033[0m")
            print(f"\033[97m[*] Visualize with: dot -Tpng {filename} -o graph.png\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Error exporting: {str(e)}\033[0m")
    
    def find_connections(self, entity_id: int, depth: int = 1):
        """Find all connections to an entity"""
        visited = set()
        connections = []
        
        def dfs(node_id, current_depth):
            if current_depth > depth or node_id in visited:
                return
            
            visited.add(node_id)
            
            for rel in self.relationships:
                if rel['source'] == node_id:
                    connections.append(rel)
                    dfs(rel['target'], current_depth + 1)
        
        dfs(entity_id, 0)
        return connections
    
    def create_investigation_template(self, target_name: str, target_email: str = None):
        """Create a basic investigation template"""
        print(f"\n\033[93m[*] Creating investigation template for: {target_name}\033[0m\n")
        
        # Central person
        person_id = self.create_person_entity(target_name, target_email)
        
        if target_email:
            # Email entity
            email_id = self.create_email_entity(target_email)
            self.add_relationship(person_id, email_id, "has email")
            
            # Extract domain from email
            if '@' in target_email:
                domain = target_email.split('@')[1]
                domain_id = self.create_domain_entity(domain)
                self.add_relationship(email_id, domain_id, "belongs to")
        
        print(f"\033[92m[+] Template created with {len(self.entities)} entities\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           MALTEGO AUTOMATION WRAPPER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[*] Link Analysis & Relationship Mapping Tool\033[0m\n")
    
    graph = MaltegoWrapper()
    
    print("\033[97mSelect mode:\033[0m")
    print("  [1] Create investigation from scratch")
    print("  [2] Create template investigation")
    print("  [3] Load existing graph (JSON)")
    
    mode = input("\n\033[95m[?] Select mode (1-3): \033[0m").strip()
    
    if mode == '1':
        # Manual graph creation
        print("\n\033[97m[*] Creating new investigation graph...\033[0m\n")
        
        while True:
            print("\033[97mEntity Types:\033[0m")
            print("  [1] Person")
            print("  [2] Domain")
            print("  [3] Email")
            print("  [4] IP Address")
            print("  [5] Phone")
            print("  [6] Social Media")
            print("  [7] Add Relationship")
            print("  [8] View Graph")
            print("  [9] Export & Exit")
            
            choice = input("\n\033[95m[?] Select action: \033[0m").strip()
            
            if choice == '1':
                name = input("\033[95m  Name: \033[0m").strip()
                email = input("\033[95m  Email (optional): \033[0m").strip() or None
                phone = input("\033[95m  Phone (optional): \033[0m").strip() or None
                entity_id = graph.create_person_entity(name, email, phone)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '2':
                domain = input("\033[95m  Domain: \033[0m").strip()
                ip = input("\033[95m  IP (optional): \033[0m").strip() or None
                entity_id = graph.create_domain_entity(domain, ip)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '3':
                email = input("\033[95m  Email: \033[0m").strip()
                entity_id = graph.create_email_entity(email)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '4':
                ip = input("\033[95m  IP Address: \033[0m").strip()
                location = input("\033[95m  Location (optional): \033[0m").strip() or None
                entity_id = graph.create_ip_entity(ip, location)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '5':
                phone = input("\033[95m  Phone: \033[0m").strip()
                carrier = input("\033[95m  Carrier (optional): \033[0m").strip() or None
                entity_id = graph.create_phone_entity(phone, carrier)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '6':
                platform = input("\033[95m  Platform: \033[0m").strip()
                username = input("\033[95m  Username: \033[0m").strip()
                url = input("\033[95m  URL (optional): \033[0m").strip() or None
                entity_id = graph.create_social_media_entity(platform, username, url)
                print(f"\033[92m[+] Created entity ID: {entity_id}\033[0m")
            
            elif choice == '7':
                source = int(input("\033[95m  Source entity ID: \033[0m").strip())
                target = int(input("\033[95m  Target entity ID: \033[0m").strip())
                rel_type = input("\033[95m  Relationship type: \033[0m").strip()
                graph.add_relationship(source, target, rel_type)
                print(f"\033[92m[+] Relationship added\033[0m")
            
            elif choice == '8':
                graph.visualize_graph_ascii()
            
            elif choice == '9':
                break
    
    elif mode == '2':
        target = input("\033[95m[?] Target name: \033[0m").strip()
        email = input("\033[95m[?] Target email (optional): \033[0m").strip() or None
        
        graph.create_investigation_template(target, email)
        graph.visualize_graph_ascii()
    
    # Export options
    print("\n\033[97mExport options:\033[0m")
    
    export_json = input("\033[95m[?] Export to JSON? (y/n): \033[0m").strip().lower()
    if export_json == 'y':
        filename = input("\033[95m[?] Filename (default: graph.json): \033[0m").strip()
        filename = filename if filename else "graph.json"
        graph.export_to_json(filename)
    
    export_dot = input("\033[95m[?] Export to Graphviz? (y/n): \033[0m").strip().lower()
    if export_dot == 'y':
        filename = input("\033[95m[?] Filename (default: graph.dot): \033[0m").strip()
        filename = filename if filename else "graph.dot"
        graph.export_to_graphviz(filename)
    
    print("\n" + "\033[92m" + "="*70)
    print("           COMPLETE")
    print("="*70 + "\033[0m")

if __name__ == "__main__":
    run()
