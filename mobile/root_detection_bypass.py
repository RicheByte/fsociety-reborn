#!/usr/bin/env python3
import os
import subprocess
import json
import base64
import hashlib
import time
from datetime import datetime

class RootDetectionBypass:
    def __init__(self):
        self.bypass_methods = {}
        self.device = None
        
        self.root_indicators = {
            'su_binaries': [
                '/system/bin/su',
                '/system/xbin/su',
                '/sbin/su',
                '/system/su',
                '/system/bin/.ext/.su',
                '/system/usr/we-need-root/su-backup',
                '/system/xbin/mu',
                '/data/local/xbin/su',
                '/data/local/bin/su',
                '/data/local/su'
            ],
            'root_apps': [
                'com.noshufou.android.su',
                'com.thirdparty.superuser',
                'eu.chainfire.supersu',
                'com.koushikdutta.superuser',
                'com.zachspong.temprootremovejb',
                'com.ramdroid.appquarantine',
                'com.topjohnwu.magisk'
            ],
            'dangerous_props': [
                '[ro.debuggable]: [1]',
                '[ro.secure]: [0]'
            ],
            'rw_paths': [
                '/system',
                '/data'
            ]
        }
        
        self.frida_hooks = self.generate_frida_hooks()
    
    def check_adb_connection(self):
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            
            devices = []
            for line in result.stdout.split('\n')[1:]:
                if '\tdevice' in line:
                    devices.append(line.split('\t')[0])
            
            return devices
        except:
            return []
    
    def execute_adb(self, command):
        if not self.device:
            return ''
        
        try:
            result = subprocess.run(
                ['adb', '-s', self.device, 'shell', command],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except:
            return ''
    
    def hide_su_binary(self):
        print(f"\033[93m[*] Hiding SU binaries...\033[0m")
        
        for su_path in self.root_indicators['su_binaries']:
            self.execute_adb(f"mount -o remount,rw {su_path}")
            self.execute_adb(f"mv {su_path} {su_path}.bak")
        
        print(f"\033[92m[+] SU binaries hidden\033[0m")
    
    def modify_build_props(self):
        print(f"\033[93m[*] Modifying build properties...\033[0m")
        
        props = {
            'ro.debuggable': '0',
            'ro.secure': '1',
            'ro.build.tags': 'release-keys',
            'ro.build.type': 'user'
        }
        
        for prop, value in props.items():
            self.execute_adb(f"setprop {prop} {value}")
        
        print(f"\033[92m[+] Build properties modified\033[0m")
    
    def hide_magisk(self):
        print(f"\033[93m[*] Hiding Magisk...\033[0m")
        
        self.execute_adb("magisk --denylist add com.example.bankingapp")
        self.execute_adb("magiskhide --add com.example.bankingapp")
        self.execute_adb("magisk --sqlite 'UPDATE policies SET logging=0'")
        
        self.execute_adb("pm hide com.topjohnwu.magisk")
        
        print(f"\033[92m[+] Magisk hidden\033[0m")
    
    def patch_safetynet(self):
        print(f"\033[93m[*] Patching SafetyNet...\033[0m")
        
        self.execute_adb("magisk resetprop ro.build.type user")
        self.execute_adb("magisk resetprop ro.debuggable 0")
        self.execute_adb("magisk resetprop ro.secure 1")
        self.execute_adb("magisk resetprop ro.build.tags release-keys")
        self.execute_adb("magisk resetprop ro.build.selinux 0")
        
        self.execute_adb("magisk resetprop --delete ro.boot.veritymode")
        self.execute_adb("magisk resetprop --delete ro.boot.verifiedbootstate")
        
        print(f"\033[92m[+] SafetyNet patches applied\033[0m")
    
    def hide_root_apps(self):
        print(f"\033[93m[*] Hiding root management apps...\033[0m")
        
        for package in self.root_indicators['root_apps']:
            self.execute_adb(f"pm hide {package}")
            self.execute_adb(f"pm disable {package}")
        
        print(f"\033[92m[+] Root apps hidden\033[0m")
    
    def patch_selinux(self):
        print(f"\033[93m[*] Patching SELinux...\033[0m")
        
        self.execute_adb("setenforce 0")
        self.execute_adb("magisk resetprop ro.build.selinux 0")
        
        print(f"\033[92m[+] SELinux permissive mode enabled\033[0m")
    
    def mount_system_ro(self):
        print(f"\033[93m[*] Remounting system as read-only...\033[0m")
        
        self.execute_adb("mount -o remount,ro /system")
        self.execute_adb("mount -o remount,ro /")
        
        print(f"\033[92m[+] System mounted as read-only\033[0m")
    
    def generate_frida_hooks(self):
        return {
            'rootbeer': '''
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    
    RootBeer.isRooted.implementation = function() {
        console.log('[+] RootBeer.isRooted() bypassed');
        return false;
    };
    
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
        console.log('[+] RootBeer.isRootedWithoutBusyBoxCheck() bypassed');
        return false;
    };
    
    RootBeer.detectRootManagementApps.implementation = function() {
        console.log('[+] RootBeer.detectRootManagementApps() bypassed');
        return false;
    };
    
    RootBeer.detectPotentiallyDangerousApps.implementation = function() {
        console.log('[+] RootBeer.detectPotentiallyDangerousApps() bypassed');
        return false;
    };
    
    RootBeer.checkForBinary.implementation = function(filename) {
        console.log('[+] RootBeer.checkForBinary(' + filename + ') bypassed');
        return false;
    };
    
    RootBeer.checkForDangerousProps.implementation = function() {
        console.log('[+] RootBeer.checkForDangerousProps() bypassed');
        return false;
    };
    
    RootBeer.checkForRWPaths.implementation = function() {
        console.log('[+] RootBeer.checkForRWPaths() bypassed');
        return false;
    };
    
    RootBeer.detectTestKeys.implementation = function() {
        console.log('[+] RootBeer.detectTestKeys() bypassed');
        return false;
    };
    
    RootBeer.checkSuExists.implementation = function() {
        console.log('[+] RootBeer.checkSuExists() bypassed');
        return false;
    };
    
    console.log('[+] RootBeer bypass loaded');
});
''',
            'file_check': '''
Java.perform(function() {
    var File = Java.use('java.io.File');
    
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        
        var suspiciousPaths = [
            'su', 'magisk', 'busybox', 'Superuser', 'SuperSU',
            'chainfire', 'koush', 'noshufou', 'xposed'
        ];
        
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (path.toLowerCase().indexOf(suspiciousPaths[i]) >= 0) {
                console.log('[+] File.exists() for ' + path + ' - returning false');
                return false;
            }
        }
        
        return this.exists();
    };
    
    File.canRead.implementation = function() {
        var path = this.getAbsolutePath();
        
        if (path.indexOf('/system') === 0 || path.indexOf('/data') === 0) {
            console.log('[+] File.canRead() for ' + path + ' - returning false');
            return false;
        }
        
        return this.canRead();
    };
    
    File.canWrite.implementation = function() {
        var path = this.getAbsolutePath();
        
        if (path.indexOf('/system') === 0) {
            console.log('[+] File.canWrite() for ' + path + ' - returning false');
            return false;
        }
        
        return this.canWrite();
    };
    
    console.log('[+] File check bypass loaded');
});
''',
            'package_manager': '''
Java.perform(function() {
    var PackageManager = Java.use('android.content.pm.PackageManager');
    
    PackageManager.getInstalledPackages.overload('int').implementation = function(flags) {
        var packages = this.getInstalledPackages(flags);
        var ArrayList = Java.use('java.util.ArrayList');
        var filteredPackages = ArrayList.$new();
        
        var suspiciousPackages = [
            'com.topjohnwu.magisk',
            'eu.chainfire.supersu',
            'com.noshufou.android.su',
            'com.koushikdutta.superuser',
            'com.thirdparty.superuser',
            'de.robv.android.xposed.installer'
        ];
        
        for (var i = 0; i < packages.size(); i++) {
            var packageInfo = packages.get(i);
            var packageName = packageInfo.packageName.value;
            
            var isSuspicious = false;
            for (var j = 0; j < suspiciousPackages.length; j++) {
                if (packageName === suspiciousPackages[j]) {
                    console.log('[+] Hiding package: ' + packageName);
                    isSuspicious = true;
                    break;
                }
            }
            
            if (!isSuspicious) {
                filteredPackages.add(packageInfo);
            }
        }
        
        return filteredPackages;
    };
    
    PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
        var suspiciousPackages = [
            'com.topjohnwu.magisk',
            'eu.chainfire.supersu',
            'com.noshufou.android.su'
        ];
        
        for (var i = 0; i < suspiciousPackages.length; i++) {
            if (packageName === suspiciousPackages[i]) {
                console.log('[+] Package not found: ' + packageName);
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
            }
        }
        
        return this.getApplicationInfo(packageName, flags);
    };
    
    console.log('[+] Package manager bypass loaded');
});
''',
            'system_properties': '''
Java.perform(function() {
    var SystemProperties = Java.use('android.os.SystemProperties');
    
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === 'ro.build.tags') {
            console.log('[+] SystemProperties.get("ro.build.tags") - returning release-keys');
            return 'release-keys';
        }
        
        if (key === 'ro.debuggable') {
            console.log('[+] SystemProperties.get("ro.debuggable") - returning 0');
            return '0';
        }
        
        if (key === 'ro.secure') {
            console.log('[+] SystemProperties.get("ro.secure") - returning 1');
            return '1';
        }
        
        if (key === 'ro.build.type') {
            console.log('[+] SystemProperties.get("ro.build.type") - returning user');
            return 'user';
        }
        
        return this.get(key);
    };
    
    console.log('[+] System properties bypass loaded');
});
''',
            'runtime_exec': '''
Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        var cmd = cmdArray.join(' ');
        
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('which') >= 0 || cmd.indexOf('busybox') >= 0) {
            console.log('[+] Runtime.exec() blocked: ' + cmd);
            throw Java.use('java.io.IOException').$new('Command not found');
        }
        
        return this.exec(cmdArray);
    };
    
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('which') >= 0 || cmd.indexOf('busybox') >= 0) {
            console.log('[+] Runtime.exec() blocked: ' + cmd);
            throw Java.use('java.io.IOException').$new('Command not found');
        }
        
        return this.exec(cmd);
    };
    
    console.log('[+] Runtime.exec bypass loaded');
});
'''
        }
    
    def inject_frida_script(self, package_name, hook_type):
        if hook_type not in self.frida_hooks:
            print(f"\033[91m[!] Unknown hook type\033[0m")
            return
        
        script_content = self.frida_hooks[hook_type]
        script_file = f"bypass_{hook_type}_{int(time.time())}.js"
        
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        print(f"\033[93m[*] Injecting {hook_type} bypass into {package_name}...\033[0m")
        
        try:
            cmd = ['frida', '-U', '-f', package_name, '-l', script_file, '--no-pause']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            print(f"\033[92m[+] Frida hook injected\033[0m")
            print(f"\033[97m[*] Press Ctrl+C to stop...\033[0m\n")
            
            try:
                for line in process.stdout:
                    print(line.strip())
            except KeyboardInterrupt:
                process.terminate()
                print(f"\n\033[92m[+] Stopped\033[0m")
            
            os.remove(script_file)
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            if os.path.exists(script_file):
                os.remove(script_file)
    
    def inject_all_hooks(self, package_name):
        combined_script = "".join(self.frida_hooks.values())
        script_file = f"bypass_all_{int(time.time())}.js"
        
        with open(script_file, 'w') as f:
            f.write(combined_script)
        
        print(f"\033[93m[*] Injecting all bypasses into {package_name}...\033[0m")
        
        try:
            cmd = ['frida', '-U', '-f', package_name, '-l', script_file, '--no-pause']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            print(f"\033[92m[+] All Frida hooks injected\033[0m")
            print(f"\033[97m[*] Press Ctrl+C to stop...\033[0m\n")
            
            try:
                for line in process.stdout:
                    print(line.strip())
            except KeyboardInterrupt:
                process.terminate()
                print(f"\n\033[92m[+] Stopped\033[0m")
            
            os.remove(script_file)
            
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            if os.path.exists(script_file):
                os.remove(script_file)
    
    def generate_bypass_report(self):
        report = {
            'timestamp': datetime.now().isoformat(),
            'device': self.device,
            'bypasses_applied': list(self.bypass_methods.keys()),
            'frida_hooks_available': list(self.frida_hooks.keys())
        }
        
        report_file = f"bypass_report_{int(time.time())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\033[92m[+] Report saved: {report_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     ROOT & JAILBREAK DETECTION BYPASS TOOL")
    print("="*70 + "\033[0m\n")
    
    bypass = RootDetectionBypass()
    
    devices = bypass.check_adb_connection()
    
    if not devices:
        print(f"\033[91m[!] No devices connected\033[0m")
        return
    
    bypass.device = devices[0]
    print(f"\033[92m[+] Device: {bypass.device}\033[0m\n")
    
    print("\033[97mBypass Options:\033[0m")
    print("\033[97m  [1] Hide SU binaries\033[0m")
    print("\033[97m  [2] Modify build properties\033[0m")
    print("\033[97m  [3] Hide Magisk\033[0m")
    print("\033[97m  [4] Patch SafetyNet\033[0m")
    print("\033[97m  [5] Hide root apps\033[0m")
    print("\033[97m  [6] Patch SELinux\033[0m")
    print("\033[97m  [7] Mount system as read-only\033[0m")
    print("\033[97m  [8] Inject Frida hook (specific)\033[0m")
    print("\033[97m  [9] Inject all Frida hooks\033[0m")
    print("\033[97m  [10] Apply all bypasses\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        bypass.hide_su_binary()
    
    elif choice == '2':
        bypass.modify_build_props()
    
    elif choice == '3':
        bypass.hide_magisk()
    
    elif choice == '4':
        bypass.patch_safetynet()
    
    elif choice == '5':
        bypass.hide_root_apps()
    
    elif choice == '6':
        bypass.patch_selinux()
    
    elif choice == '7':
        bypass.mount_system_ro()
    
    elif choice == '8':
        package = input("\033[95m[?] Target package name: \033[0m").strip()
        
        print("\n\033[97mAvailable hooks:\033[0m")
        hooks = list(bypass.frida_hooks.keys())
        for i, hook in enumerate(hooks, 1):
            print(f"\033[97m  [{i}] {hook}\033[0m")
        
        hook_choice = input(f"\n\033[95m[?] Select hook: \033[0m").strip()
        
        if hook_choice.isdigit() and 1 <= int(hook_choice) <= len(hooks):
            hook_type = hooks[int(hook_choice) - 1]
            bypass.inject_frida_script(package, hook_type)
    
    elif choice == '9':
        package = input("\033[95m[?] Target package name: \033[0m").strip()
        bypass.inject_all_hooks(package)
    
    elif choice == '10':
        bypass.hide_su_binary()
        bypass.modify_build_props()
        bypass.hide_magisk()
        bypass.patch_safetynet()
        bypass.hide_root_apps()
        bypass.patch_selinux()
        bypass.mount_system_ro()
        
        print(f"\n\033[92m[+] All bypasses applied\033[0m")
    
    bypass.generate_bypass_report()
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
