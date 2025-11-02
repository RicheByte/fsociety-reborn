"""
Image Metadata Analyzer
Extracts EXIF data from images including GPS coordinates
"""
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
from datetime import datetime

class ImageMetadataAnalyzer:
    def __init__(self):
        self.metadata = {}
        
    def extract_exif(self, image_path: str) -> dict:
        """Extract EXIF data from image"""
        print(f"\n\033[93m[*] Analyzing: {os.path.basename(image_path)}\033[0m\n")
        
        try:
            image = Image.open(image_path)
            exif_data = image._getexif()
            
            if exif_data is None:
                print(f"\033[91m[!] No EXIF data found in this image\033[0m")
                return {}
            
            metadata = {}
            
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata[tag] = value
            
            return metadata
            
        except Exception as e:
            print(f"\033[91m[!] Error reading image: {str(e)}\033[0m")
            return {}
    
    def extract_gps(self, exif_data: dict) -> dict:
        """Extract GPS coordinates from EXIF data"""
        gps_info = {}
        
        if 'GPSInfo' in exif_data:
            gps_data = exif_data['GPSInfo']
            
            for tag_id in gps_data.keys():
                tag = GPSTAGS.get(tag_id, tag_id)
                gps_info[tag] = gps_data[tag_id]
            
            # Convert to decimal degrees
            if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                lat = self.convert_to_degrees(gps_info['GPSLatitude'])
                lon = self.convert_to_degrees(gps_info['GPSLongitude'])
                
                # Handle North/South and East/West
                if gps_info.get('GPSLatitudeRef') == 'S':
                    lat = -lat
                if gps_info.get('GPSLongitudeRef') == 'W':
                    lon = -lon
                
                gps_info['DecimalLatitude'] = lat
                gps_info['DecimalLongitude'] = lon
                gps_info['GoogleMapsURL'] = f"https://www.google.com/maps?q={lat},{lon}"
        
        return gps_info
    
    def convert_to_degrees(self, value):
        """Convert GPS coordinates to degrees"""
        d, m, s = value
        return float(d) + (float(m) / 60.0) + (float(s) / 3600.0)
    
    def display_metadata(self, metadata: dict):
        """Display extracted metadata"""
        important_tags = [
            'Make', 'Model', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
            'Software', 'ExposureTime', 'FNumber', 'ISO', 'FocalLength',
            'Flash', 'Orientation', 'XResolution', 'YResolution',
            'Artist', 'Copyright', 'ImageDescription'
        ]
        
        print(f"\033[92m[+] Image Metadata:\033[0m\n")
        
        # Display important tags first
        for tag in important_tags:
            if tag in metadata:
                value = metadata[tag]
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except:
                        value = str(value)
                print(f"\033[97m  {tag}: {value}\033[0m")
        
        # Display GPS information if available
        gps_info = self.extract_gps(metadata)
        
        if gps_info:
            print(f"\n\033[92m[+] GPS Information:\033[0m\n")
            
            if 'DecimalLatitude' in gps_info:
                print(f"\033[97m  Latitude: {gps_info['DecimalLatitude']}\033[0m")
                print(f"\033[97m  Longitude: {gps_info['DecimalLongitude']}\033[0m")
                print(f"\033[92m  Google Maps: {gps_info['GoogleMapsURL']}\033[0m")
            
            for key, value in gps_info.items():
                if key not in ['DecimalLatitude', 'DecimalLongitude', 'GoogleMapsURL']:
                    print(f"\033[97m  {key}: {value}\033[0m")
    
    def analyze_multiple_images(self, directory: str):
        """Analyze all images in a directory"""
        print(f"\n\033[93m[*] Analyzing images in: {directory}\033[0m\n")
        
        image_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.bmp', '.gif']
        results = {}
        
        try:
            files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
            image_files = [f for f in files if os.path.splitext(f)[1].lower() in image_extensions]
            
            print(f"\033[97m[*] Found {len(image_files)} image files\033[0m\n")
            
            for image_file in image_files:
                image_path = os.path.join(directory, image_file)
                metadata = self.extract_exif(image_path)
                
                if metadata:
                    results[image_file] = metadata
                    self.display_metadata(metadata)
                    print("\n" + "-"*70 + "\n")
            
            return results
            
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
            return {}
    
    def strip_metadata(self, image_path: str, output_path: str = None):
        """Remove all EXIF data from an image"""
        try:
            if output_path is None:
                name, ext = os.path.splitext(image_path)
                output_path = f"{name}_stripped{ext}"
            
            image = Image.open(image_path)
            
            # Create image without EXIF
            data = list(image.getdata())
            image_without_exif = Image.new(image.mode, image.size)
            image_without_exif.putdata(data)
            
            image_without_exif.save(output_path)
            
            print(f"\n\033[92m[+] Metadata stripped and saved to: {output_path}\033[0m")
            
        except Exception as e:
            print(f"\n\033[91m[!] Error stripping metadata: {str(e)}\033[0m")
    
    def save_metadata_report(self, metadata: dict, output_file: str):
        """Save metadata to text file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("Image Metadata Analysis Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")
                
                for key, value in metadata.items():
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8')
                        except:
                            value = f"<binary data: {len(value)} bytes>"
                    f.write(f"{key}: {value}\n")
                
                # GPS Info
                gps_info = self.extract_gps(metadata)
                if gps_info:
                    f.write("\n" + "="*70 + "\n")
                    f.write("GPS INFORMATION\n")
                    f.write("="*70 + "\n\n")
                    for key, value in gps_info.items():
                        f.write(f"{key}: {value}\n")
            
            print(f"\n\033[92m[+] Report saved to: {output_file}\033[0m")
            
        except Exception as e:
            print(f"\n\033[91m[!] Error saving report: {str(e)}\033[0m")

def run():
    """Main function"""
    print("\033[92m" + "="*70)
    print("           IMAGE METADATA ANALYZER")
    print("="*70 + "\033[0m\n")
    
    print("\033[97mSelect option:\033[0m")
    print("  [1] Analyze single image")
    print("  [2] Analyze all images in directory")
    print("  [3] Strip metadata from image")
    
    option = input("\n\033[95m[?] Select option (1-3): \033[0m").strip()
    
    analyzer = ImageMetadataAnalyzer()
    
    if option == '1':
        image_path = input("\033[95m[?] Enter image path: \033[0m").strip()
        
        if not os.path.exists(image_path):
            print(f"\033[91m[!] File not found: {image_path}\033[0m")
            return
        
        metadata = analyzer.extract_exif(image_path)
        
        if metadata:
            analyzer.display_metadata(metadata)
            
            save = input("\n\033[95m[?] Save report to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = input("\033[95m[?] Enter filename (default: metadata_report.txt): \033[0m").strip()
                filename = filename if filename else "metadata_report.txt"
                analyzer.save_metadata_report(metadata, filename)
    
    elif option == '2':
        directory = input("\033[95m[?] Enter directory path: \033[0m").strip()
        
        if not os.path.exists(directory):
            print(f"\033[91m[!] Directory not found: {directory}\033[0m")
            return
        
        results = analyzer.analyze_multiple_images(directory)
        
        print(f"\n\033[92m[+] Analyzed {len(results)} images with EXIF data\033[0m")
    
    elif option == '3':
        image_path = input("\033[95m[?] Enter image path: \033[0m").strip()
        
        if not os.path.exists(image_path):
            print(f"\033[91m[!] File not found: {image_path}\033[0m")
            return
        
        output_path = input("\033[95m[?] Enter output path (press Enter for auto): \033[0m").strip()
        output_path = output_path if output_path else None
        
        analyzer.strip_metadata(image_path, output_path)
    
    print("\n" + "\033[92m" + "="*70)
    print("           ANALYSIS COMPLETE")
    print("="*70 + "\033[0m")

if __name__ == "__main__":
    run()
