# surveillance_recon/core/streamer.py
# [SecOps Research // Live Stream Validator & Auto-Capture Engine v2.2]
# For authorized red team reconnaissance under Security Research Protocol §7. Use only in legally authorized environments.

import os
import re
import time
import subprocess
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, quote

class StreamValidator:
    """
    Advanced stream validator that confirms real video streams
    and captures preview frames using headless VLC or FFmpeg.
    """

    def __init__(
        self,
        target_ip: str,
        port: int,
        auth: Optional[Tuple[str, str]] = None,
        capture_dir: str = "screenshots",
        timeout: int = 10
    ):
        self.target_ip = target_ip
        self.port = port
        self.auth = auth
        self.capture_dir = capture_dir
        self.timeout = timeout
        self.base_url = f"http://{target_ip}:{port}"
        os.makedirs(self.capture_dir, exist_ok=True)

        # Common stream paths per brand (extendable)
        self.stream_paths = {
            "rtsp": [
                "/Streaming/Channels/101",
                "/cam/realmonitor",
                "/h264",
                "/video",
                "/live",
                "/stream",
                "/cam0_0",
                "/11",
                "/ch0_0.h264"
            ],
            "http": [
                "/video.mjpeg",
                "/mjpg/video.mjpg",
                "/axis-cgi/mjpg/video.cgi",
                "/videostream.cgi",
                "/live/mjpeg",
                "/cgi-bin/mjpg/video.cgi",
                "/snapshot.cgi"
            ],
            "rtmp": [
                "/live/stream",
                "/app/stream"
            ],
            "mms": [
                "/stream"
            ]
        }

    def _build_auth_url(self, base_url: str) -> str:
        """Inject auth into URL if credentials exist"""
        if not self.auth:
            return base_url
        username, password = self.auth
        parsed = list(urljoin(base_url, "").split("://"))
        if len(parsed) == 2:
            scheme, rest = parsed
            if scheme in ("rtsp", "http", "https"):
                auth_str = f"{quote(username)}:{quote(password)}@"
                return f"{scheme}://{auth_str}{rest}"
        return base_url

    def _probe_stream_raw(self, url: str, protocol: str) -> bool:
        """Low-level stream validation by reading raw bytes"""
        try:
            if protocol == "rtsp":
                # RTSP requires OPTIONS/DESCRIBE — too complex for raw; defer to VLC
                return self._test_with_vlc(url)
            elif protocol == "http":
                headers = {"Range": "bytes=0-1023"}
                if self.auth:
                    from requests.auth import HTTPBasicAuth
                    r = requests.get(
                        url,
                        auth=HTTPBasicAuth(*self.auth),
                        headers=headers,
                        timeout=self.timeout,
                        stream=True
                    )
                else:
                    r = requests.get(url, headers=headers, timeout=self.timeout, stream=True)
                if r.status_code in (200, 206):
                    chunk = next(r.iter_content(chunk_size=1024))
                    # Check for video signatures
                    if b"mdat" in chunk or b"ftyp" in chunk or b"Content-Type: multipart" in chunk:
                        return True
            elif protocol in ("rtmp", "mms"):
                # Use FFmpeg probe
                return self._test_with_ffmpeg(url)
        except:
            pass
        return False

    def _test_with_vlc(self, url: str) -> bool:
        """Use VLC headless to validate stream"""
        try:
            cmd = [
                "cvlc", url,
                "--intf", "dummy",
                "--play-and-exit",
                "--timeout", str(self.timeout),
                "--network-caching=1000"
            ]
            if self.auth:
                cmd.extend(["--rtsp-user", self.auth[0], "--rtsp-pwd", self.auth[1]])
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout + 2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False

    def _test_with_ffmpeg(self, url: str) -> bool:
        """Use FFmpeg to probe stream metadata"""
        try:
            cmd = ["ffmpeg", "-v", "quiet", "-i", url, "-t", "1", "-f", "null", "-"]
            if self.auth:
                env = os.environ.copy()
                env["FFMPEG_RTSP_USERNAME"] = self.auth[0]
                env["FFMPEG_RTSP_PASSWORD"] = self.auth[1]
                result = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout + 2)
            else:
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout + 2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False

    def _capture_frame_vlc(self, url: str, output_path: str) -> bool:
        """Capture single frame using VLC"""
        try:
            cmd = [
                "vlc", url,
                "--intf", "dummy",
                "--video-filter", "scene",
                "--scene-path", os.path.dirname(output_path),
                "--scene-prefix", os.path.basename(output_path).split('.')[0],
                "--scene-format", "jpg",
                "--scene-replace",
                "--scene-ratio", "24",  # Capture 1st frame
                "--run-time=1",
                "--play-and-exit"
            ]
            if self.auth:
                cmd.extend(["--rtsp-user", self.auth[0], "--rtsp-pwd", self.auth[1]])
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            return os.path.exists(output_path)
        except:
            return False

    def detect_streams(self, brand: str = "generic") -> List[Dict]:
        """Scan for live streams across protocols and paths"""
        results = []
        tested_urls = set()

        # Generate candidate URLs
        candidates = []

        # RTSP candidates
        for path in self.stream_paths["rtsp"]:
            url = f"rtsp://{self.target_ip}:{self.port if self.port != 80 else 554}{path}"
            candidates.append(("rtsp", url))

        # HTTP candidates
        for path in self.stream_paths["http"]:
            url = f"http://{self.target_ip}:{self.port}{path}"
            candidates.append(("http", url))

        # RTMP/MMS (less common)
        if self.port in (1935, 80, 443):
            for path in self.stream_paths["rtmp"]:
                url = f"rtmp://{self.target_ip}{path}"
                candidates.append(("rtmp", url))
        if self.port == 1755:
            for path in self.stream_paths["mms"]:
                url = f"mms://{self.target_ip}{path}"
                candidates.append(("mms", url))

        # Brand-specific additions
        if "hikvision" in brand.lower():
            candidates.append(("rtsp", f"rtsp://{self.target_ip}:554/Streaming/Channels/101"))
        elif "dahua" in brand.lower():
            candidates.append(("rtsp", f"rtsp://{self.target_ip}:554/cam/realmonitor?channel=1&subtype=0"))
        elif "cp plus" in brand.lower():
            candidates.append(("http", f"http://{self.target_ip}:{self.port}/video.mjpeg"))

        # Deduplicate
        unique_candidates = []
        for proto, url in candidates:
            if url not in tested_urls:
                tested_urls.add(url)
                unique_candidates.append((proto, url))

        # Validate streams
        for proto, url in unique_candidates:
            print(f"[~] Testing {url} ...")
            if self._probe_stream_raw(url, proto):
                # Auth-embedded URL for usability
                playable_url = self._build_auth_url(url)
                screenshot_path = os.path.join(
                    self.capture_dir,
                    f"{self.target_ip}_{self.port}_{proto}.jpg"
                )
                captured = self._capture_frame_vlc(url, screenshot_path)

                results.append({
                    "protocol": proto.upper(),
                    "stream_url": url,
                    "playable_url": playable_url,
                    "is_live": True,
                    "screenshot_captured": captured,
                    "screenshot_path": screenshot_path if captured else None
                })

        return results

    def get_playable_links(self, streams: List[Dict]) -> Dict[str, str]:
        """Generate user-friendly playback instructions"""
        links = {}
        for stream in streams:
            url = stream["playable_url"]
            proto = stream["protocol"]
            if proto == "RTSP":
                links["VLC"] = f"Open in VLC: {url}"
                links["FFplay"] = f"ffplay '{url}'"
            elif proto == "HTTP":
                links["Browser"] = f"Open in browser: {url}"
                links["VLC"] = f"Open in VLC: {url}"
        return links
