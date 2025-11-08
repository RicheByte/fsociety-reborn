#!/usr/bin/env python3
import os
import subprocess
import json
import time
import hashlib
import base64
from datetime import datetime

class FridaScriptRunner:
    def __init__(self):
        self.scripts = {}
        self.sessions = {}
        self.hooks = []
        
        self.script_templates = {
            'ssl_pinning_bypass': self.generate_ssl_bypass(),
            'root_detection_bypass': self.generate_root_bypass(),
            'crypto_hook': self.generate_crypto_hook(),
            'api_interceptor': self.generate_api_interceptor(),
            'method_tracer': self.generate_method_tracer(),
            'memory_dumper': self.generate_memory_dumper(),
            'class_enumerator': self.generate_class_enum(),
            'native_hook': self.generate_native_hook()
        }
    
    def generate_ssl_bypass(self):
        return '''
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    
    ApiClient.checkTrustedRecursive.implementation = function(a1,a2,a3,a4,a5,a6) {
        console.log('[+] SSL Pinning Bypass: checkTrustedRecursive');
        return array_list.$new();
    }
    
    ApiClient.verifyHostname.implementation = function(hostname, session) {
        console.log('[+] SSL Pinning Bypass: verifyHostname for ' + hostname);
        return true;
    }
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var EmptyTrustManager = Java.registerClass({
        name: 'com.sensepost.test.EmptyTrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManager = [EmptyTrustManager.$new()];
    var TLS_SSLContext = SSLContext.getInstance("TLS");
    TLS_SSLContext.init(null, TrustManager, null);
    SSLContext.setDefault.implementation = function(ctx) {
        console.log('[+] SSLContext.setDefault() bypassed');
    }
    
    console.log('[+] SSL Pinning bypass loaded');
});
'''
    
    def generate_root_bypass(self):
        return '''
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    
    RootBeer.isRooted.implementation = function() {
        console.log('[+] Root Detection: isRooted called - returning false');
        return false;
    }
    
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
        console.log('[+] Root Detection: isRootedWithoutBusyBoxCheck - returning false');
        return false;
    }
    
    RootBeer.detectRootManagementApps.implementation = function() {
        console.log('[+] Root Detection: detectRootManagementApps - returning false');
        return false;
    }
    
    RootBeer.detectPotentiallyDangerousApps.implementation = function() {
        console.log('[+] Root Detection: detectPotentiallyDangerousApps - returning false');
        return false;
    }
    
    RootBeer.checkForBinary.implementation = function(filename) {
        console.log('[+] Root Detection: checkForBinary(' + filename + ') - returning false');
        return false;
    }
    
    RootBeer.checkForDangerousProps.implementation = function() {
        console.log('[+] Root Detection: checkForDangerousProps - returning false');
        return false;
    }
    
    RootBeer.checkForRWPaths.implementation = function() {
        console.log('[+] Root Detection: checkForRWPaths - returning false');
        return false;
    }
    
    RootBeer.detectTestKeys.implementation = function() {
        console.log('[+] Root Detection: detectTestKeys - returning false');
        return false;
    }
    
    RootBeer.checkSuExists.implementation = function() {
        console.log('[+] Root Detection: checkSuExists - returning false');
        return false;
    }
    
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.build.tags') {
            console.log('[+] SystemProperties.get("ro.build.tags") - returning release-keys');
            return 'release-keys';
        }
        return this.get(key);
    }
    
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') >= 0 || path.indexOf('magisk') >= 0 || 
            path.indexOf('busybox') >= 0 || path.indexOf('Superuser') >= 0) {
            console.log('[+] File.exists() for ' + path + ' - returning false');
            return false;
        }
        return this.exists();
    }
    
    console.log('[+] Root detection bypass loaded');
});
'''
    
    def generate_crypto_hook(self):
        return '''
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    
    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        console.log('[+] Cipher.getInstance("' + transformation + '")');
        return this.getInstance(transformation);
    }
    
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        console.log('[+] Cipher.init() mode: ' + (opmode === 1 ? 'ENCRYPT' : 'DECRYPT'));
        
        if (key.getClass().getName() === 'javax.crypto.spec.SecretKeySpec') {
            var keyBytes = key.getEncoded();
            console.log('[+] Key: ' + bytesToHex(keyBytes));
        }
        
        return this.init(opmode, key);
    }
    
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
        console.log('[+] Cipher.init() mode: ' + (opmode === 1 ? 'ENCRYPT' : 'DECRYPT'));
        
        if (key.getClass().getName() === 'javax.crypto.spec.SecretKeySpec') {
            var keyBytes = key.getEncoded();
            console.log('[+] Key: ' + bytesToHex(keyBytes));
        }
        
        if (params.getClass().getName() === 'javax.crypto.spec.IvParameterSpec') {
            var ivBytes = params.getIV();
            console.log('[+] IV: ' + bytesToHex(ivBytes));
        }
        
        return this.init(opmode, key, params);
    }
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[+] Cipher.doFinal() input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[+] Cipher.doFinal() output: ' + bytesToHex(result));
        return result;
    }
    
    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < Math.min(bytes.length, 32); i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex + (bytes.length > 32 ? '...' : '');
    }
    
    console.log('[+] Crypto hooks loaded');
});
'''
    
    def generate_api_interceptor(self):
        return '''
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var RequestBody = Java.use('okhttp3.RequestBody');
    var Response = Java.use('okhttp3.Response');
    var ResponseBody = Java.use('okhttp3.ResponseBody');
    var Buffer = Java.use('okio.Buffer');
    
    var Interceptor = Java.registerClass({
        name: 'com.frida.CustomInterceptor',
        implements: [Java.use('okhttp3.Interceptor')],
        methods: {
            intercept: function(chain) {
                var request = chain.request();
                var url = request.url().toString();
                var method = request.method();
                
                console.log('[+] HTTP Request:');
                console.log('    Method: ' + method);
                console.log('    URL: ' + url);
                
                var headers = request.headers();
                for (var i = 0; i < headers.size(); i++) {
                    console.log('    Header: ' + headers.name(i) + ': ' + headers.value(i));
                }
                
                var requestBody = request.body();
                if (requestBody != null) {
                    var buffer = Buffer.$new();
                    requestBody.writeTo(buffer);
                    var body = buffer.readUtf8();
                    console.log('    Body: ' + body);
                }
                
                var response = chain.proceed(request);
                
                console.log('[+] HTTP Response:');
                console.log('    Code: ' + response.code());
                console.log('    Message: ' + response.message());
                
                var responseBody = response.body();
                if (responseBody != null) {
                    var source = responseBody.source();
                    source.request(Java.use('java.lang.Long').MAX_VALUE.value);
                    var buffer = source.buffer();
                    var bodyString = buffer.clone().readUtf8();
                    console.log('    Body: ' + bodyString.substring(0, Math.min(bodyString.length, 500)));
                }
                
                return response;
            }
        }
    });
    
    OkHttpClient.$init.overload().implementation = function() {
        var result = this.$init();
        this.interceptors().add(Interceptor.$new());
        console.log('[+] OkHttpClient interceptor added');
        return result;
    }
    
    console.log('[+] API interceptor loaded');
});
'''
    
    def generate_method_tracer(self):
        return '''
Java.perform(function() {
    var targetClass = '{TARGET_CLASS}';
    var Class = Java.use(targetClass);
    
    var methods = Class.class.getDeclaredMethods();
    console.log('[+] Tracing ' + methods.length + ' methods in ' + targetClass);
    
    methods.forEach(function(method) {
        var methodName = method.getName();
        var overloads = Class[methodName];
        
        if (overloads) {
            overloads.implementation = function() {
                console.log('[+] ' + targetClass + '.' + methodName + '() called');
                console.log('    Arguments: ' + Array.prototype.slice.call(arguments));
                
                var result = this[methodName].apply(this, arguments);
                
                console.log('    Return: ' + result);
                return result;
            }
        }
    });
    
    console.log('[+] Method tracer loaded for ' + targetClass);
});
'''
    
    def generate_memory_dumper(self):
        return '''
Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    var System = Java.use('java.lang.System');
    var ActivityThread = Java.use('android.app.ActivityThread');
    
    function dumpMemory() {
        var currentApplication = ActivityThread.currentApplication();
        var context = currentApplication.getApplicationContext();
        var packageName = context.getPackageName();
        
        console.log('[+] Dumping memory for: ' + packageName);
        
        var runtime = Runtime.getRuntime();
        var maxMemory = runtime.maxMemory() / 1024 / 1024;
        var totalMemory = runtime.totalMemory() / 1024 / 1024;
        var freeMemory = runtime.freeMemory() / 1024 / 1024;
        
        console.log('[+] Max Memory: ' + maxMemory + ' MB');
        console.log('[+] Total Memory: ' + totalMemory + ' MB');
        console.log('[+] Free Memory: ' + freeMemory + ' MB');
        console.log('[+] Used Memory: ' + (totalMemory - freeMemory) + ' MB');
        
        var classes = Java.enumerateLoadedClassesSync();
        console.log('[+] Loaded classes: ' + classes.length);
        
        classes.slice(0, 20).forEach(function(className) {
            console.log('    ' + className);
        });
    }
    
    setTimeout(dumpMemory, 1000);
    
    console.log('[+] Memory dumper loaded');
});
'''
    
    def generate_class_enum(self):
        return '''
Java.perform(function() {
    console.log('[+] Enumerating loaded classes...');
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('com.') === 0 || className.indexOf('android.') === 0) {
                console.log('[+] Class: ' + className);
                
                try {
                    var Class = Java.use(className);
                    var methods = Class.class.getDeclaredMethods();
                    
                    if (methods.length > 0) {
                        console.log('    Methods:');
                        for (var i = 0; i < Math.min(methods.length, 5); i++) {
                            console.log('      ' + methods[i].getName());
                        }
                    }
                } catch(e) {}
            }
        },
        onComplete: function() {
            console.log('[+] Class enumeration complete');
        }
    });
});
'''
    
    def generate_native_hook(self):
        return '''
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        console.log('[+] open() called: ' + path);
    },
    onLeave: function(retval) {
        console.log('[+] open() returned: ' + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
    },
    onLeave: function(retval) {
        if (retval.toInt32() > 0) {
            var data = Memory.readByteArray(this.buf, Math.min(retval.toInt32(), 64));
            console.log('[+] read() fd=' + this.fd + ' count=' + this.count + ' data=' + hexdump(data, {length: 64}));
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "write"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var buf = args[1];
        var count = args[2].toInt32();
        
        var data = Memory.readByteArray(buf, Math.min(count, 64));
        console.log('[+] write() fd=' + fd + ' count=' + count + ' data=' + hexdump(data, {length: 64}));
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
    onEnter: function(args) {
        this.str1 = Memory.readUtf8String(args[0]);
        this.str2 = Memory.readUtf8String(args[1]);
    },
    onLeave: function(retval) {
        console.log('[+] strcmp("' + this.str1 + '", "' + this.str2 + '") = ' + retval.toInt32());
    }
});

console.log('[+] Native hooks loaded');
'''
    
    def list_processes(self):
        try:
            result = subprocess.run(['frida-ps', '-U'], capture_output=True, text=True, timeout=10)
            processes = []
            
            for line in result.stdout.split('\n')[2:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[0]
                        name = ' '.join(parts[1:])
                        processes.append({'pid': pid, 'name': name})
            
            return processes
        except:
            return []
    
    def execute_script(self, package_name, script_content):
        script_file = f"frida_script_{int(time.time())}.js"
        
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        print(f"\033[93m[*] Executing Frida script on {package_name}...\033[0m")
        
        try:
            cmd = ['frida', '-U', '-f', package_name, '-l', script_file, '--no-pause']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            print(f"\033[92m[+] Script injected. Process ID: {process.pid}\033[0m")
            print(f"\033[97m[*] Press Ctrl+C to stop...\033[0m\n")
            
            try:
                for line in process.stdout:
                    print(line.strip())
            except KeyboardInterrupt:
                process.terminate()
                print(f"\n\033[92m[+] Script execution stopped\033[0m")
            
            os.remove(script_file)
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            if os.path.exists(script_file):
                os.remove(script_file)

def run():
    print("\033[92m" + "="*70)
    print("     ADVANCED FRIDA SCRIPT RUNNER")
    print("="*70 + "\033[0m\n")
    
    runner = FridaScriptRunner()
    
    print("\033[97mAvailable script templates:\033[0m")
    templates = list(runner.script_templates.keys())
    for i, template in enumerate(templates, 1):
        print(f"\033[97m  [{i}] {template.replace('_', ' ').title()}\033[0m")
    
    print("\033[97m  [9] List running processes\033[0m")
    print("\033[97m  [10] Custom script\033[0m")
    
    choice = input(f"\n\033[95m[?] Select template: \033[0m").strip()
    
    if choice == '9':
        print(f"\n\033[93m[*] Listing processes...\033[0m\n")
        processes = runner.list_processes()
        
        for proc in processes[:20]:
            print(f"\033[97m  PID: {proc['pid']:>6}  Name: {proc['name']}\033[0m")
        
        print(f"\n\033[92m[+] Total processes: {len(processes)}\033[0m")
    
    elif choice == '10':
        script_file = input("\033[95m[?] Script file path: \033[0m").strip()
        
        if os.path.exists(script_file):
            with open(script_file, 'r') as f:
                script_content = f.read()
            
            package = input("\033[95m[?] Target package name: \033[0m").strip()
            runner.execute_script(package, script_content)
        else:
            print(f"\033[91m[!] File not found\033[0m")
    
    elif choice.isdigit() and 1 <= int(choice) <= len(templates):
        template_name = templates[int(choice) - 1]
        script_content = runner.script_templates[template_name]
        
        package = input("\033[95m[?] Target package name: \033[0m").strip()
        
        if template_name == 'method_tracer':
            target_class = input("\033[95m[?] Target class name: \033[0m").strip()
            script_content = script_content.replace('{TARGET_CLASS}', target_class)
        
        runner.execute_script(package, script_content)
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
