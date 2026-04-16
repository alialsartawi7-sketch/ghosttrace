"""ExifTool Adapter — Smart Metadata Intelligence"""
import json
import re
from tools.base import ToolAdapter


class ExifToolAdapter(ToolAdapter):
    name = "ExifTool"
    cmd = "exiftool"
    result_type = "metadata"
    description = "File metadata extraction with intelligence classification"

    # ═══════════ HIGH VALUE — the stuff that matters for OSINT ═══════════
    HIGH_VALUE = {
        # GPS = gold mine
        "GPSLatitude", "GPSLongitude", "GPSPosition", "GPSAltitude",
        "GPSDateStamp", "GPSTimeStamp", "GPSMapDatum",
        # Author / Owner
        "Author", "Creator", "Artist", "Copyright", "OwnerName",
        "CameraOwnerName", "ByLine", "Credit",
        # Device identification
        "Make", "Model", "LensModel", "LensInfo", "SerialNumber",
        "InternalSerialNumber", "LensSerialNumber",
        # Software / editing
        "Software", "HistorySoftwareAgent", "CreatorTool",
        # Dates (when was this taken?)
        "DateTimeOriginal", "CreateDate", "ModifyDate",
        "DateCreated", "TimeCreated",
        # Document info
        "Title", "Subject", "Description", "Comment", "Keywords",
        "Producer", "PDFVersion",
        # Network / email
        "XMPToolkit", "MetadataDate",
    }

    # ═══════════ BASIC — file properties (low intelligence value) ═══════════
    NOISE_KEYS = {
        "ExifToolVersion", "FileName", "Directory", "FileSize",
        "FileModifyDate", "FileAccessDate", "FileInodeChangeDate",
        "FilePermissions", "FileType", "FileTypeExtension",
        "MIMEType", "ExifByteOrder", "Orientation",
        "XResolution", "YResolution", "ResolutionUnit",
        "BitsPerSample", "ColorComponents", "ColorSpace",
        "YCbCrSubSampling", "YCbCrPositioning",
        "EncodingProcess", "JFIFVersion", "ProfileCMMType",
        "ProfileVersion", "ProfileClass", "ProfileConnectionSpace",
        "ProfileDateTime", "ProfileFileSignature", "PrimaryPlatform",
        "CMMFlags", "DeviceManufacturer", "DeviceModel",
        "DeviceAttributes", "RenderingIntent", "ConnectionSpaceIlluminant",
        "ProfileCreator", "ProfileID", "ProfileDescription",
        "ProfileCopyright", "MediaWhitePoint", "MediaBlackPoint",
        "RedMatrixColumn", "GreenMatrixColumn", "BlueMatrixColumn",
        "RedTRC", "GreenTRC", "BlueTRC", "ChromaticAdaptation",
        "ImageWidth", "ImageHeight", "ImageSize", "Megapixels",
        "SourceFile", "ThumbnailImage", "ThumbnailLength", "ThumbnailOffset",
        "Compression", "PhotometricInterpretation", "SamplesPerPixel",
        "PlanarConfiguration", "StripOffsets", "RowsPerStrip",
        "StripByteCounts",
    }

    # ═══════════ Metadata stripping signatures ═══════════
    STRIPPING_SIGNATURES = {
        "whatsapp": {"pattern": re.compile(r'whatsapp', re.I),
                     "msg": "WhatsApp strips GPS, camera, and author metadata from shared images"},
        "telegram": {"pattern": re.compile(r'telegram', re.I),
                     "msg": "Telegram strips most EXIF metadata from shared images"},
        "signal": {"pattern": re.compile(r'signal', re.I),
                   "msg": "Signal strips all metadata for privacy protection"},
        "twitter": {"pattern": re.compile(r'twitter|tweet', re.I),
                    "msg": "Twitter/X strips EXIF data from uploaded images"},
        "facebook": {"pattern": re.compile(r'facebook|fb_|messenger', re.I),
                     "msg": "Facebook strips GPS and personal metadata from uploads"},
        "screenshot": {"pattern": re.compile(r'screenshot|screen.?shot|screen.?cap', re.I),
                       "msg": "Screenshots contain no camera/GPS data (device screen capture)"},
    }

    def build_command(self, target, **opts):
        return [self.cmd, "-json", target]

    def parse_line(self, line, context):
        return []

    def parse_json(self, json_str):
        """Parse ExifTool JSON with smart intelligence classification"""
        results = []
        try:
            data = json.loads(json_str)
            meta = data[0] if data else {}
        except (json.JSONDecodeError, IndexError):
            return results

        filename = meta.get("FileName", "")
        high_found = []
        basic_count = 0

        # ── 1. Check for metadata stripping ──
        all_text = f"{filename} {meta.get('Software', '')} {meta.get('Comment', '')}"
        for source, sig in self.STRIPPING_SIGNATURES.items():
            if sig["pattern"].search(all_text):
                results.insert(0, {
                    "value": f"⚠ {sig['msg']}",
                    "source": self.name,
                    "type": "metadata",
                    "confidence": 0.95,
                    "extra": "WARNING"
                })
                break

        # ── 2. HIGH VALUE fields first ──
        for key in self.HIGH_VALUE:
            if key in meta:
                val = str(meta[key]).strip()
                if not val or val.lower() in ("", "none", "unknown", "0", "(binary data)"):
                    continue
                # GPS = highest value
                if key.startswith("GPS"):
                    conf = 0.98
                    tag = "GPS"
                # Author/Owner = very high
                elif key in ("Author", "Creator", "Artist", "OwnerName", "CameraOwnerName", "Copyright"):
                    conf = 0.95
                    tag = "AUTHOR"
                # Device = high
                elif key in ("Make", "Model", "SerialNumber", "LensModel"):
                    conf = 0.92
                    tag = "DEVICE"
                # Software
                elif key in ("Software", "CreatorTool", "Producer"):
                    conf = 0.85
                    tag = "SOFTWARE"
                # Dates
                elif "Date" in key or "Time" in key:
                    conf = 0.85
                    tag = "DATE"
                else:
                    conf = 0.8
                    tag = "INFO"

                results.append({
                    "value": f"{key}: {val[:200]}",
                    "source": self.name,
                    "type": "metadata",
                    "confidence": conf,
                    "extra": tag
                })
                high_found.append(key)

        # ── 3. BASIC fields (low confidence, collapsed) ──
        basic_items = []
        for key, val in meta.items():
            if key in self.HIGH_VALUE or key in ("SourceFile",):
                continue
            val_str = str(val).strip()
            if not val_str or val_str.lower() in ("", "none", "(binary data)"):
                continue

            if key in self.NOISE_KEYS:
                # Only include a few basic ones with low confidence
                if key in ("ImageWidth", "ImageHeight", "FileSize", "FileType"):
                    results.append({
                        "value": f"{key}: {val_str[:200]}",
                        "source": self.name,
                        "type": "metadata",
                        "confidence": 0.4,
                        "extra": "BASIC"
                    })
                basic_count += 1
            else:
                # Unknown field — might be interesting
                results.append({
                    "value": f"{key}: {val_str[:200]}",
                    "source": self.name,
                    "type": "metadata",
                    "confidence": 0.6,
                    "extra": "OTHER"
                })

        # ── 4. Intelligence summary ──
        if not high_found:
            results.append({
                "value": "No sensitive metadata found (GPS, author, device info stripped or absent)",
                "source": self.name,
                "type": "metadata",
                "confidence": 0.9,
                "extra": "SUMMARY"
            })
        else:
            tags = set()
            if any(k.startswith("GPS") for k in high_found): tags.add("📍 GPS location")
            if any(k in ("Author","Creator","Artist","OwnerName") for k in high_found): tags.add("👤 Author/owner")
            if any(k in ("Make","Model") for k in high_found): tags.add("📱 Device info")
            if any(k in ("Software","CreatorTool") for k in high_found): tags.add("💻 Software")
            results.insert(0, {
                "value": f"Sensitive metadata detected: {', '.join(sorted(tags))}",
                "source": self.name,
                "type": "metadata",
                "confidence": 0.98,
                "extra": "SUMMARY"
            })

        # ── 5. Stats ──
        results.append({
            "value": f"Total fields: {len(meta)-1} ({len(high_found)} high-value, {basic_count} basic)",
            "source": self.name,
            "type": "metadata",
            "confidence": 0.5,
            "extra": "STATS"
        })

        return results
