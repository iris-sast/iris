#!/usr/bin/env python3
"""
Simple HTTP server for IRIS Results Visualizer
"""

import http.server
import socketserver
import os
import json
import urllib.parse
from pathlib import Path
import csv

def load_config():
    """Load configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    
    if not os.path.exists(config_path):
        # Create default config if it doesn't exist
        default_config = {
            "server": {
                "port": 8000,
                "host": "localhost"
            },
            "paths": {
                "outputs_dir": "../output",
                "project_sources_dir": "../data/project-sources",
                "project_info_csv": "../data/project_info.csv"
            },
            "ui": {
                "max_source_code_height": "600px",
                "default_project": "perwendel__spark_CVE-2018-9159_2.7.1"
            },
            "api": {
                "base_url": "http://localhost:8000/api"
            }
        }
        
        with open(config_path, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Resolve relative paths relative to the config file location
        config_dir = os.path.dirname(config_path)
        if 'paths' in config:
            for key, path in config['paths'].items():
                if not os.path.isabs(path):
                    config['paths'][key] = os.path.join(config_dir, path)
        
        # Ensure project_info_csv path exists in configuration
        if 'paths' not in config:
            config['paths'] = {}
        if 'project_info_csv' not in config['paths']:
            default_csv_path = os.path.join(os.path.dirname(__file__), '../data/project_info.csv')
            config['paths']['project_info_csv'] = default_csv_path
        else:
            # Resolve relative path for project_info_csv
            csv_path = config['paths']['project_info_csv']
            if not os.path.isabs(csv_path):
                config['paths']['project_info_csv'] = os.path.join(config_dir, csv_path)
        
        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

# Load configuration
CONFIG = load_config()
if not CONFIG:
    print("Failed to load configuration. Using defaults.")
    CONFIG = {
        "server": {"port": 8000, "host": "localhost"},
        "paths": {
            "outputs_dir": os.path.join(os.path.dirname(__file__), "../outputs"),
            "project_sources_dir": os.path.join(os.path.dirname(__file__), "../data/project-sources"),
            "project_info_csv": os.path.join(os.path.dirname(__file__), "../data/project_info.csv")
        },
        "ui": {"max_source_code_height": "600px", "default_project": "perwendel__spark_CVE-2018-9159_2.7.1"},
        "api": {"base_url": "http://localhost:8000/api"}
    }

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
class IRISVisualizerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        server_root = os.path.dirname(os.path.abspath(__file__))
        super().__init__(*args, directory=server_root, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Handle API requests
        if path.startswith('/api/'):
            self.handle_api_request(path[4:])  # Remove '/api/' prefix
            return
        
        # Handle static files
        if path == '/':
            path = '/index.html'
        
        # Set appropriate content types
        if path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
        elif path.endswith('.css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
        elif path.endswith('.js'):
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
        elif path.endswith('.json'):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
        else:
            # Let the parent class handle other files
            return super().do_GET()
        
        self.end_headers()
        
        # Read and send file content
        try:
            file_path = os.path.join(BASE_DIR, path.lstrip('/'))
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "File not found")
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def handle_api_request(self, path):
        """Handle API requests"""
        try:
            # Strip leading slash if present
            path = path.lstrip('/')
            
            print(f"API request - original path: {self.path}")
            print(f"API request - stripped path: {path}")
            
            # Parse the full URL to get query parameters
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            if path.startswith('sarif/'):
                print(f"API request - handling SARIF: {path[6:]}")
                self.handle_sarif_request(path[6:])  # Remove 'sarif/' prefix
            elif path.startswith('source/'):
                self.handle_source_request(path[7:])  # Remove 'source/' prefix
            elif path == 'projects':
                self.handle_projects_request()
            elif path == 'cwes':
                self.handle_cwes_request()
            elif path == 'config':
                self.handle_config_request()
            elif path == 'models':
                self.handle_models_request(query_params)
            elif path == 'project_cwes':
                self.handle_project_cwes_request(query_params)
            elif path == 'source_projects':
                self.handle_source_projects_request()
            elif path.startswith('local_file/'):
                self.handle_local_file_request(path[11:])  # Remove 'local_file/' prefix
            elif path.startswith('project_metadata/'):
                self.handle_project_metadata_request(path[17:])  # Remove 'project_metadata/' prefix
            elif path == 'dir':
                self.handle_dir_request(query_params)
            else:
                self.send_error(404, "API endpoint not found")
        except Exception as e:
            self.send_error(500, f"API error: {str(e)}")
    
    def handle_sarif_request(self, file_path):
        """Handle SARIF file requests"""
        # URL-decode the file path
        decoded_path = urllib.parse.unquote(file_path)
        
        # Resolve relative path from server directory
        sarif_path = Path(CONFIG['paths']['outputs_dir'])
        if not sarif_path.is_absolute():
            sarif_path = Path(__file__).parent / sarif_path
        
        sarif_path = sarif_path / decoded_path
        
        print(f"SARIF request - original file_path: {file_path}")
        print(f"SARIF request - decoded file_path: {decoded_path}")
        print(f"SARIF request - full path: {sarif_path}")
        print(f"SARIF request - exists: {sarif_path.exists()}")
        
        if not sarif_path.exists():
            self.send_error(404, f"SARIF file not found: {decoded_path}")
            return
        
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(sarif_data).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error reading SARIF file: {str(e)}")
    
    def handle_source_request(self, file_path):
        """Handle source code file requests"""
        # URL-decode the file path
        decoded_path = urllib.parse.unquote(file_path)
        
        print(f"SOURCE request - original file_path: {file_path}")
        print(f"SOURCE request - decoded file_path: {decoded_path}")
        
        # Extract project name from file path
        parts = decoded_path.split('/', 1)
        if len(parts) < 2:
            self.send_error(400, "Invalid source file path")
            return
        
        sarif_project_name, relative_path = parts
        print(f"SOURCE request - sarif_project_name: {sarif_project_name}")
        print(f"SOURCE request - relative_path: {relative_path}")
        
        # Try to find the file in available source projects
        # First try the exact project name, then try alternative versions
        source_projects = []
        source_path = Path(CONFIG['paths']['project_sources_dir'])
        
        # Resolve relative path from server directory
        if not source_path.is_absolute():
            source_path = Path(__file__).parent / source_path
        
        print(f"SOURCE request - source_path: {source_path}")
        print(f"SOURCE request - source_path exists: {source_path.exists()}")
        
        if source_path.exists():
            for project_dir in source_path.iterdir():
                if project_dir.is_dir():
                    source_projects.append(project_dir.name)
        
        print(f"SOURCE request - available source projects: {source_projects}")
        
        # Try to find a matching project
        target_project = None
        if sarif_project_name in source_projects:
            target_project = sarif_project_name
            print(f"SOURCE request - exact match found: {target_project}")
        else:
            # Try to find a project with the same base name
            base_project_name = sarif_project_name.split('_CVE-')[0]
            print(f"SOURCE request - base_project_name: {base_project_name}")
            for source_project in source_projects:
                if source_project.startswith(base_project_name):
                    target_project = source_project
                    print(f"SOURCE request - base name match found: {target_project}")
                    break
        
        if not target_project:
            print(f"SOURCE request - no matching project found")
            self.send_error(404, f"No source project found for: {sarif_project_name}")
            return
        
        # Construct the full source path
        source_file_path = source_path / target_project / relative_path
        print(f"SOURCE request - full source path: {source_file_path}")
        print(f"SOURCE request - file exists: {source_file_path.exists()}")
        
        if not source_file_path.exists():
            self.send_error(404, f"Source file not found: {relative_path} in project {target_project}")
            return
        
        try:
            with open(source_file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Return as JSON with content and metadata
            response_data = {
                'content': source_code,
                'project': target_project,
                'file_path': relative_path
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error reading source file: {str(e)}")
    
    def handle_projects_request(self):
        """Handle projects list request"""
        try:
            projects = []
            outputs_path = Path(CONFIG['paths']['outputs_dir'])
            
            # Resolve relative path from server directory
            if not outputs_path.is_absolute():
                outputs_path = Path(__file__).parent / outputs_path
            
            if outputs_path.exists():
                for project_dir in outputs_path.iterdir():
                    if project_dir.is_dir() and not project_dir.name.endswith('.tar.gz'):
                        projects.append(project_dir.name)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(projects).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error listing projects: {str(e)}")
    
    def handle_cwes_request(self):
        """Handle CWEs list request"""
        try:
            cwes = []
            outputs_path = Path(CONFIG['paths']['outputs_dir'])
            
            if outputs_path.exists():
                for project_dir in outputs_path.iterdir():
                    if project_dir.is_dir() and not project_dir.name.endswith('.tar.gz'):
                        for run_id_dir in project_dir.iterdir():
                            if run_id_dir.is_dir():
                                for cwe_dir in run_id_dir.iterdir():
                                    if cwe_dir.is_dir() and cwe_dir.name.startswith('cwe-'):
                                        cwes.append(cwe_dir.name)
            
            # Remove duplicates and sort
            cwes = sorted(list(set(cwes)))
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(cwes).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error listing CWEs: {str(e)}")
    
    def handle_models_request(self, query_params):
        """Handle models list request for a specific project"""
        try:
            project_name = query_params.get('project', [None])[0]
            
            if not project_name:
                self.send_error(400, "Project parameter required")
                return
            
            models = []
            project_path = Path(CONFIG['paths']['outputs_dir']) / project_name
            
            if project_path.exists() and project_path.is_dir():
                for run_id_dir in project_path.iterdir():
                    if run_id_dir.is_dir():
                        # Only include run-ids that have cwe-XXX folders
                        has_cwe_folders = False
                        for cwe_dir in run_id_dir.iterdir():
                            if cwe_dir.is_dir() and cwe_dir.name.startswith('cwe-'):
                                has_cwe_folders = True
                                break
                        
                        if has_cwe_folders:
                            models.append(run_id_dir.name)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(models).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error listing models: {str(e)}")
    
    def handle_project_cwes_request(self, query_params):
        """Handle CWEs list request for a specific project"""
        try:
            project_name = query_params.get('project', [None])[0]
            
            if not project_name:
                self.send_error(400, "Project parameter required")
                return
            
            cwes = []
            project_path = Path(CONFIG['paths']['outputs_dir']) / project_name
            
            if project_path.exists() and project_path.is_dir():
                for run_id_dir in project_path.iterdir():
                    if run_id_dir.is_dir():
                        for cwe_dir in run_id_dir.iterdir():
                            # Include all cwe-XXX folders
                            if cwe_dir.is_dir() and cwe_dir.name.startswith('cwe-'):
                                cwes.append(cwe_dir.name)
            
            # Remove duplicates and sort
            cwes = sorted(list(set(cwes)))
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(cwes).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error listing project CWEs: {str(e)}")
    
    def handle_config_request(self):
        """Handle configuration request"""
        try:
            # Return a sanitized version of config (without sensitive paths)
            client_config = {
                "ui": CONFIG.get("ui", {})
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(client_config).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error returning config: {str(e)}")
    
    def handle_source_projects_request(self):
        """Handle source projects list request"""
        try:
            projects = []
            source_path = Path(CONFIG['paths']['project_sources_dir'])
            
            if source_path.exists():
                for project_dir in source_path.iterdir():
                    if project_dir.is_dir():
                        projects.append(project_dir.name)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(projects).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error listing source projects: {str(e)}")
    
    def handle_local_file_request(self, file_path):
        """Handle local file request with line highlighting"""
        try:
            # URL-decode the file path
            decoded_path = urllib.parse.unquote(file_path)
            
            # Parse query parameters for line number
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            highlight_line = query_params.get('line', [None])[0]
            
            # Get the currently selected project from the request
            project_name = query_params.get('project', [None])[0]
            
            if not project_name:
                self.send_error(400, "Project parameter required")
                return
            
            # Try to find the file in available source projects
            # First try the exact project name, then try alternative versions
            source_projects = []
            source_path = Path(CONFIG['paths']['project_sources_dir'])
            
            # Resolve relative path from server directory
            if not source_path.is_absolute():
                source_path = Path(__file__).parent / source_path
            
            if source_path.exists():
                for project_dir in source_path.iterdir():
                    if project_dir.is_dir():
                        source_projects.append(project_dir.name)
            
            # Try to find a matching project
            target_project = None
            if project_name in source_projects:
                target_project = project_name
            else:
                # Try to find a project with the same base name
                base_project_name = project_name.split('_CVE-')[0]
                for source_project in source_projects:
                    if source_project.startswith(base_project_name):
                        target_project = source_project
                        break
            
            if not target_project:
                self.send_error(404, f"No source project found for: {project_name}")
                return
            
            # Construct the full file path
            full_path = source_path / target_project / decoded_path
            
            if not full_path.exists():
                self.send_error(404, f"Local file not found: {decoded_path} in project {target_project}")
                return
            
            # Read the file content
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create HTML with line highlighting
            lines = content.split('\n')
            html_lines = []
            
            for i, line in enumerate(lines, 1):
                line_class = 'highlighted-line' if highlight_line and str(i) == highlight_line else ''
                html_lines.append(f'<div class="code-line {line_class}" id="line-{i}">')
                html_lines.append(f'<span class="line-number">{i}</span>')
                html_lines.append(f'<span class="line-content">{escape_html(line)}</span>')
                html_lines.append('</div>')
            
            # Create the HTML page
            html_content = f'''
<!DOCTYPE html>
<html>
<head>
    <title>{decoded_path} - Line {highlight_line or 'All'}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; margin: 0; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
        .code-line {{ display: flex; padding: 2px 8px; }}
        .line-number {{ min-width: 50px; color: #858585; text-align: right; margin-right: 15px; user-select: none; }}
        .line-content {{ flex: 1; white-space: pre; }}
        .highlighted-line {{ background-color: #264f78; border-left: 3px solid #007acc; }}
        .file-header {{ background: #2d2d30; padding: 10px; margin-bottom: 20px; border-radius: 5px; }}
        .file-header h1 {{ margin: 0; font-size: 18px; }}
        .file-header .line-info {{ color: #858585; font-size: 14px; }}
        .file-header .project-info {{ color: #858585; font-size: 12px; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="file-header">
        <h1>{decoded_path}</h1>
        {f'<div class="line-info">Highlighted line: {highlight_line}</div>' if highlight_line else ''}
        <div class="project-info">Source project: {target_project}</div>
    </div>
    <div class="code-container">
        {''.join(html_lines)}
    </div>
    <script>
        // Scroll to highlighted line if specified
        {f'document.getElementById("line-{highlight_line}").scrollIntoView({{behavior: "smooth", block: "center"}});' if highlight_line else ''}
    </script>
</body>
</html>
            '''
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Error serving local file: {str(e)}")

    def handle_project_metadata_request(self, project_id):
        """Get project metadata from project_info.csv"""
        try:
            # URL-decode the project_id
            decoded_project_id = urllib.parse.unquote(project_id)
            
            # The CSV file is in the data directory, which is one level up from outputs
            csv_path = CONFIG['paths']['project_info_csv']
            
            if not os.path.exists(csv_path):
                self.send_error(404, 'Project info CSV not found')
                return
            
            print(f"Searching for project_id: {decoded_project_id}")
            print(f"CSV path: {csv_path}")
            
            with open(csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                # Debug: Print first few project_slugs to see what's available
                projects_found = []
                for i, row in enumerate(reader):
                    if i < 5:  # Print first 5 projects for debugging
                        print(f"CSV row {i}: project_slug = '{row['project_slug']}'")
                    projects_found.append(row['project_slug'])
                    
                    if row['project_slug'] == decoded_project_id:
                        print(f"Found matching project: {decoded_project_id}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            'cve_id': row['cve_id'] or None,
                            'cwe_id': row['cwe_id'] or None,
                            'cwe_name': row['cwe_name'] or None,
                            'github_username': row['github_username'] or None,
                            'github_repository_name': row['github_repository_name'] or None,
                            'github_tag': row['github_tag'] or None,
                            'github_url': row['github_url'] or None,
                            'advisory_id': row['advisory_id'] or None,
                            'buggy_commit_id': row['buggy_commit_id'] or None,
                            'fix_commit_ids': row['fix_commit_ids'] or None
                        }).encode('utf-8'))
                        return
            
            print(f"Project '{decoded_project_id}' not found. Available projects (first 10): {projects_found[:10]}")
            self.send_error(404, 'Project not found')
            
        except Exception as e:
            print(f"Error in handle_project_metadata_request: {str(e)}")
            self.send_error(500, f'Error reading project metadata: {str(e)}')

    def handle_dir_request(self, query_params):
        """Return a directory listing inside a source project"""
        try:
            project_name = query_params.get('project', [None])[0]
            rel_path = query_params.get('path', [''])[0]  # default to project root

            if not project_name:
                self.send_error(400, "Project parameter required")
                return

            # Resolve the base directory for this project
            base_dir = Path(CONFIG['paths']['project_sources_dir']) / project_name
            if not base_dir.exists() or not base_dir.is_dir():
                self.send_error(404, f"Source project '{project_name}' not found")
                return

            # Sanitize the requested path to avoid directory traversal
            requested_path = (base_dir / rel_path).resolve()
            if not str(requested_path).startswith(str(base_dir.resolve())):
                self.send_error(400, "Invalid path")
                return

            if not requested_path.exists() or not requested_path.is_dir():
                self.send_error(404, f"Directory not found: {rel_path}")
                return

            # Enumerate contents
            directories = []
            files = []
            for child in requested_path.iterdir():
                if child.is_dir():
                    directories.append(child.name)
                elif child.is_file():
                    files.append(child.name)

            directories.sort()
            files.sort()

            response = {
                'path': rel_path,
                'directories': directories,
                'files': files
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error listing directory: {str(e)}")

    def log_message(self, format, *args):
        """Custom logging to show requests"""
        print(f"[{self.log_date_time_string()}] {format % args}")

def escape_html(text):
    """Escape HTML characters"""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def main():
    """Start the server"""
    port = CONFIG['server']['port']
    host = CONFIG['server']['host']
    
    with socketserver.TCPServer((host, port), IRISVisualizerHandler) as httpd:
        print(f"IRIS Visualizer server starting on http://{host}:{port}")
        print(f"Outputs directory: {CONFIG['paths']['outputs_dir']}")
        print(f"Project sources directory: {CONFIG['paths']['project_sources_dir']}")
        print("Press Ctrl+C to stop the server")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.shutdown()

if __name__ == "__main__":
    main()
