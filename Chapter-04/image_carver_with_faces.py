import re
import zlib
import cv2
from kamene.all import *
from pathlib import Path
import argparse

pictures_directory = Path("pic_carver/pictures")
faces_directory = Path("pic_carver/faces")
pictures_directory.mkdir(parents=True, exist_ok=True)
faces_directory.mkdir(parents=True, exist_ok=True)

def face_detect(path, file_name, pcap_file):
    img = cv2.imread(str(path))
    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.CASCADE_SCALE_IMAGE, (20, 20))
    
    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
    
    output_path = faces_directory / f"{pcap_file}-{file_name}"
    cv2.imwrite(str(output_path), img)
    return True

def get_http_headers(http_payload):
    try:
        headers_raw = http_payload.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
        headers = dict(re.findall(r"(.*?): (.*?)\r\n", headers_raw))
        return headers if "Content-Type" in headers else None
    except:
        return None

def extract_image(headers, http_payload):
    try:
        if "image" not in headers.get("Content-Type", ""):
            return None, None
        image_type = headers["Content-Type"].split("/")[1]
        image = http_payload.split(b"\r\n\r\n", 1)[1]
        if "Content-Encoding" in headers:
            encoding = headers["Content-Encoding"]
            if encoding == "gzip":
                image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
            elif encoding == "deflate":
                image = zlib.decompress(image)
        return image, image_type
    except:
        return None, None

def http_assembler(pcap_file):
    carved_images = 0
    faces_detected = 0
    packets = rdpcap(pcap_file)
    sessions = packets.sessions()

    for session in sessions:
        http_payload = b""
        for packet in sessions[session]:
            try:
                if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    http_payload += bytes(packet[TCP].payload)
            except:
                continue

        headers = get_http_headers(http_payload)
        if headers is None:
            continue

        image, image_type = extract_image(headers, http_payload)
        if image and image_type:
            file_name = f"{Path(pcap_file).stem}-pic_carver_{carved_images}.{image_type}"
            image_path = pictures_directory / file_name
            with open(image_path, "wb") as img_file:
                img_file.write(image)
            carved_images += 1

            try:
                if face_detect(image_path, file_name, Path(pcap_file).stem):
                    faces_detected += 1
            except:
                continue

    return carved_images, faces_detected

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract images and faces from HTTP PCAP stream.")
    parser.add_argument("-p", "--pcap", default="bhp.pcap", help="PCAP file to analyze")
    args = parser.parse_args()

    carved_images, faces_detected = http_assembler(args.pcap)
    print(f"[+] Extracted {carved_images} image(s)")
    print(f"[+] Detected {faces_detected} face(s)")
