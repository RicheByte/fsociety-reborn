#!/usr/bin/env python3
import os
import subprocess
import time
import json
import random
import math
from datetime import datetime

class MobileLocationSpoofer:
    def __init__(self):
        self.current_lat = 0.0
        self.current_lon = 0.0
        self.altitude = 0.0
        self.speed = 0.0
        self.accuracy = 20.0
        
        self.famous_locations = {
            'times_square': (40.758896, -73.985130),
            'eiffel_tower': (48.858844, 2.294351),
            'big_ben': (51.500729, -0.124625),
            'statue_of_liberty': (40.689247, -74.044502),
            'sydney_opera': (-33.856784, 151.215297),
            'burj_khalifa': (25.197197, 55.274376),
            'golden_gate': (37.819929, -122.478255),
            'mount_fuji': (35.360555, 138.727778),
            'taj_mahal': (27.175015, 78.042155),
            'colosseum': (41.890210, 12.492231)
        }
    
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
    
    def set_mock_location_android(self, device, latitude, longitude, altitude=0):
        commands = [
            f'adb -s {device} shell settings put secure mock_location 1',
            f'adb -s {device} shell appops set android MOCK_LOCATION allow',
            f'adb -s {device} shell am start -n io.appium.settings/.Settings -e longitude {longitude} -e latitude {latitude} -e altitude {altitude}'
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), capture_output=True, timeout=5)
            except:
                pass
        
        print(f"\033[92m[+] Location set to: {latitude}, {longitude}\033[0m")
    
    def spoof_gps_coordinates(self, latitude, longitude, altitude=0):
        devices = self.check_adb_connection()
        
        if not devices:
            print(f"\033[91m[!] No devices connected\033[0m")
            return
        
        device = devices[0]
        
        self.current_lat = latitude
        self.current_lon = longitude
        self.altitude = altitude
        
        self.set_mock_location_android(device, latitude, longitude, altitude)
        
        nmea_sentence = self.generate_nmea_sentence(latitude, longitude, altitude)
        
        try:
            subprocess.run([
                'adb', '-s', device, 'shell',
                f'echo "{nmea_sentence}" > /data/local/tmp/gps.nmea'
            ], timeout=5)
        except:
            pass
    
    def generate_nmea_sentence(self, latitude, longitude, altitude):
        lat_deg = int(abs(latitude))
        lat_min = (abs(latitude) - lat_deg) * 60
        lat_dir = 'N' if latitude >= 0 else 'S'
        
        lon_deg = int(abs(longitude))
        lon_min = (abs(longitude) - lon_deg) * 60
        lon_dir = 'E' if longitude >= 0 else 'W'
        
        timestamp = time.strftime('%H%M%S', time.gmtime())
        
        sentence = f"GPGGA,{timestamp},{lat_deg:02d}{lat_min:07.4f},{lat_dir},{lon_deg:03d}{lon_min:07.4f},{lon_dir},1,08,0.9,{altitude:.1f},M,46.9,M,,"
        
        checksum = 0
        for char in sentence:
            checksum ^= ord(char)
        
        return f"${sentence}*{checksum:02X}"
    
    def simulate_route(self, start_coords, end_coords, duration_seconds, speed_kmh=50):
        devices = self.check_adb_connection()
        
        if not devices:
            print(f"\033[91m[!] No devices connected\033[0m")
            return
        
        device = devices[0]
        
        start_lat, start_lon = start_coords
        end_lat, end_lon = end_coords
        
        distance_km = self.haversine_distance(start_lat, start_lon, end_lat, end_lon)
        
        steps = int(duration_seconds / 2)
        
        print(f"\033[93m[*] Simulating route: {distance_km:.2f} km over {duration_seconds}s\033[0m")
        print(f"\033[93m[*] Speed: {speed_kmh} km/h, Steps: {steps}\033[0m")
        
        for i in range(steps + 1):
            progress = i / steps
            
            current_lat = start_lat + (end_lat - start_lat) * progress
            current_lon = start_lon + (end_lon - start_lon) * progress
            
            altitude = 100 + random.uniform(-20, 20)
            
            self.set_mock_location_android(device, current_lat, current_lon, altitude)
            
            if i % 10 == 0:
                print(f"\033[97m[*] Progress: {progress*100:.1f}% - Lat: {current_lat:.6f}, Lon: {current_lon:.6f}\033[0m")
            
            time.sleep(2)
        
        print(f"\033[92m[+] Route simulation complete\033[0m")
    
    def haversine_distance(self, lat1, lon1, lat2, lon2):
        R = 6371
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def create_circular_route(self, center_lat, center_lon, radius_km, points=20):
        devices = self.check_adb_connection()
        
        if not devices:
            print(f"\033[91m[!] No devices connected\033[0m")
            return
        
        device = devices[0]
        
        print(f"\033[93m[*] Creating circular route around {center_lat}, {center_lon}\033[0m")
        print(f"\033[93m[*] Radius: {radius_km} km, Points: {points}\033[0m")
        
        for i in range(points):
            angle = (2 * math.pi * i) / points
            
            lat_offset = (radius_km / 111.0) * math.cos(angle)
            lon_offset = (radius_km / (111.0 * math.cos(math.radians(center_lat)))) * math.sin(angle)
            
            current_lat = center_lat + lat_offset
            current_lon = center_lon + lon_offset
            
            altitude = 100 + random.uniform(-30, 30)
            
            self.set_mock_location_android(device, current_lat, current_lon, altitude)
            
            print(f"\033[97m[*] Point {i+1}/{points} - Lat: {current_lat:.6f}, Lon: {current_lon:.6f}\033[0m")
            
            time.sleep(3)
        
        print(f"\033[92m[+] Circular route complete\033[0m")
    
    def randomize_location(self, center_lat, center_lon, radius_km, duration_seconds):
        devices = self.check_adb_connection()
        
        if not devices:
            print(f"\033[91m[!] No devices connected\033[0m")
            return
        
        device = devices[0]
        
        print(f"\033[93m[*] Randomizing location within {radius_km} km radius\033[0m")
        
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            angle = random.uniform(0, 2 * math.pi)
            distance = random.uniform(0, radius_km)
            
            lat_offset = (distance / 111.0) * math.cos(angle)
            lon_offset = (distance / (111.0 * math.cos(math.radians(center_lat)))) * math.sin(angle)
            
            current_lat = center_lat + lat_offset
            current_lon = center_lon + lon_offset
            
            altitude = random.uniform(50, 200)
            
            self.set_mock_location_android(device, current_lat, current_lon, altitude)
            
            print(f"\033[97m[*] Random location: {current_lat:.6f}, {current_lon:.6f}\033[0m")
            
            time.sleep(5)
        
        print(f"\033[92m[+] Random location updates complete\033[0m")
    
    def spoof_speed(self, speed_kmh):
        self.speed = speed_kmh
        
        speed_mps = speed_kmh / 3.6
        
        print(f"\033[92m[+] Speed set to: {speed_kmh} km/h ({speed_mps:.2f} m/s)\033[0m")
    
    def spoof_altitude(self, altitude_meters):
        self.altitude = altitude_meters
        
        devices = self.check_adb_connection()
        
        if devices:
            device = devices[0]
            
            self.set_mock_location_android(device, self.current_lat, self.current_lon, altitude_meters)
        
        print(f"\033[92m[+] Altitude set to: {altitude_meters} meters\033[0m")
    
    def create_location_history(self, num_points=50):
        history = []
        
        base_lat = random.uniform(-90, 90)
        base_lon = random.uniform(-180, 180)
        
        for i in range(num_points):
            lat_offset = random.uniform(-0.1, 0.1)
            lon_offset = random.uniform(-0.1, 0.1)
            
            lat = base_lat + lat_offset
            lon = base_lon + lon_offset
            
            timestamp = datetime.now().timestamp() - (num_points - i) * 3600
            
            history.append({
                'latitude': lat,
                'longitude': lon,
                'altitude': random.uniform(0, 500),
                'accuracy': random.uniform(5, 50),
                'speed': random.uniform(0, 30),
                'timestamp': timestamp,
                'provider': 'gps'
            })
        
        history_file = f"location_history_{int(datetime.now().timestamp())}.json"
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
        
        print(f"\033[92m[+] Location history saved: {history_file}\033[0m")
        print(f"\033[92m[+] Generated {num_points} location points\033[0m")
    
    def bypass_geofencing(self, target_lat, target_lon, safe_lat, safe_lon, check_interval=10):
        devices = self.check_adb_connection()
        
        if not devices:
            print(f"\033[91m[!] No devices connected\033[0m")
            return
        
        device = devices[0]
        
        print(f"\033[93m[*] Geofencing bypass activated\033[0m")
        print(f"\033[93m[*] Target location: {target_lat}, {target_lon}\033[0m")
        print(f"\033[93m[*] Safe location: {safe_lat}, {safe_lon}\033[0m")
        
        use_target = True
        
        try:
            while True:
                if use_target:
                    self.set_mock_location_android(device, target_lat, target_lon, 100)
                    print(f"\033[97m[*] Using target location\033[0m")
                else:
                    self.set_mock_location_android(device, safe_lat, safe_lon, 100)
                    print(f"\033[97m[*] Using safe location\033[0m")
                
                use_target = not use_target
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print(f"\n\033[92m[+] Geofencing bypass stopped\033[0m")
    
    def export_spoofed_location(self):
        location_data = {
            'latitude': self.current_lat,
            'longitude': self.current_lon,
            'altitude': self.altitude,
            'speed': self.speed,
            'accuracy': self.accuracy,
            'timestamp': datetime.now().isoformat(),
            'provider': 'mock'
        }
        
        export_file = f"spoofed_location_{int(datetime.now().timestamp())}.json"
        
        with open(export_file, 'w') as f:
            json.dump(location_data, f, indent=2)
        
        print(f"\033[92m[+] Location data exported: {export_file}\033[0m")

def run():
    print("\033[92m" + "="*70)
    print("     MOBILE LOCATION SPOOFER")
    print("="*70 + "\033[0m\n")
    
    spoofer = MobileLocationSpoofer()
    
    print("\033[97mLocation Spoofing Options:\033[0m")
    print("\033[97m  [1] Spoof to custom coordinates\033[0m")
    print("\033[97m  [2] Spoof to famous location\033[0m")
    print("\033[97m  [3] Simulate route between two points\033[0m")
    print("\033[97m  [4] Create circular route\033[0m")
    print("\033[97m  [5] Random location updates\033[0m")
    print("\033[97m  [6] Generate fake location history\033[0m")
    print("\033[97m  [7] Geofencing bypass\033[0m")
    
    choice = input(f"\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        lat = float(input("\033[95m[?] Latitude: \033[0m"))
        lon = float(input("\033[95m[?] Longitude: \033[0m"))
        alt = float(input("\033[95m[?] Altitude (meters): \033[0m") or "0")
        
        spoofer.spoof_gps_coordinates(lat, lon, alt)
    
    elif choice == '2':
        print("\n\033[97mFamous Locations:\033[0m")
        for i, (name, coords) in enumerate(spoofer.famous_locations.items(), 1):
            print(f"\033[97m  [{i}] {name.replace('_', ' ').title()}: {coords[0]}, {coords[1]}\033[0m")
        
        loc_choice = input(f"\n\033[95m[?] Select location: \033[0m").strip()
        
        if loc_choice.isdigit() and 1 <= int(loc_choice) <= len(spoofer.famous_locations):
            location_name = list(spoofer.famous_locations.keys())[int(loc_choice) - 1]
            coords = spoofer.famous_locations[location_name]
            
            spoofer.spoof_gps_coordinates(coords[0], coords[1], 100)
    
    elif choice == '3':
        print("\n\033[97m[*] Start location:\033[0m")
        start_lat = float(input("\033[95m[?] Latitude: \033[0m"))
        start_lon = float(input("\033[95m[?] Longitude: \033[0m"))
        
        print("\n\033[97m[*] End location:\033[0m")
        end_lat = float(input("\033[95m[?] Latitude: \033[0m"))
        end_lon = float(input("\033[95m[?] Longitude: \033[0m"))
        
        duration = int(input("\033[95m[?] Duration (seconds): \033[0m") or "60")
        speed = float(input("\033[95m[?] Speed (km/h): \033[0m") or "50")
        
        spoofer.simulate_route((start_lat, start_lon), (end_lat, end_lon), duration, speed)
    
    elif choice == '4':
        center_lat = float(input("\033[95m[?] Center latitude: \033[0m"))
        center_lon = float(input("\033[95m[?] Center longitude: \033[0m"))
        radius = float(input("\033[95m[?] Radius (km): \033[0m") or "1")
        points = int(input("\033[95m[?] Number of points: \033[0m") or "20")
        
        spoofer.create_circular_route(center_lat, center_lon, radius, points)
    
    elif choice == '5':
        center_lat = float(input("\033[95m[?] Center latitude: \033[0m"))
        center_lon = float(input("\033[95m[?] Center longitude: \033[0m"))
        radius = float(input("\033[95m[?] Radius (km): \033[0m") or "5")
        duration = int(input("\033[95m[?] Duration (seconds): \033[0m") or "60")
        
        spoofer.randomize_location(center_lat, center_lon, radius, duration)
    
    elif choice == '6':
        num_points = int(input("\033[95m[?] Number of points: \033[0m") or "50")
        
        spoofer.create_location_history(num_points)
    
    elif choice == '7':
        print("\n\033[97m[*] Target location (restricted):\033[0m")
        target_lat = float(input("\033[95m[?] Latitude: \033[0m"))
        target_lon = float(input("\033[95m[?] Longitude: \033[0m"))
        
        print("\n\033[97m[*] Safe location:\033[0m")
        safe_lat = float(input("\033[95m[?] Latitude: \033[0m"))
        safe_lon = float(input("\033[95m[?] Longitude: \033[0m"))
        
        interval = int(input("\033[95m[?] Check interval (seconds): \033[0m") or "10")
        
        spoofer.bypass_geofencing(target_lat, target_lon, safe_lat, safe_lon, interval)
    
    print(f"\n\033[92m[+] Done\033[0m")

if __name__ == "__main__":
    run()
