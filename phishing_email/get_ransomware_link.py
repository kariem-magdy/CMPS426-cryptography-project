import requests
import re

class PhishingLinkGenerator:
    def __init__(self):
        bitly_token = "3a68309b0d3ec794728c30caacecee9be2be07f4"
        self.api_url = "https://api-ssl.bitly.com/v4/shorten"
        self.headers = {
            "Authorization": f"Bearer {bitly_token}",
            "Content-Type": "application/json"
        }

    # Convert Google Drive share link to direct download link
    def convert_drive_to_direct(self, share_link):
        match = re.search(r'/d/([a-zA-Z0-9_-]+)', share_link)
        if not match:
            raise ValueError("Invalid Google Drive link format.")
        file_id = match.group(1)
        return f"https://drive.google.com/uc?export=download&id={file_id}"

    # Shorten the link using Bitly API
    def shorten_with_bitly(self, long_url, custom_alias=None):
        data = {"long_url": long_url}
        
        # if custom_alias:
        #     # Only works if allowed on your account
        #     data["domain"] = "bit.ly"
        #     data["custom_bitlink"] = f"bit.ly/{custom_alias}"

        
        response = requests.post(self.api_url, headers=self.headers, json=data)
        if response.status_code in (200, 201):
            return response.json()["link"]
        else:
            raise Exception(f"Bitly error: {response.status_code} {response.text}")

    def run(self, google_drive_share_link):
        try:
            direct_link = self.convert_drive_to_direct(google_drive_share_link)
            print("Direct download link:", direct_link)

            short_link = self.shorten_with_bitly(direct_link)
            print("Shortened Bitly link:", short_link)

            return direct_link
        except Exception as e:
            print("Error:", e)
            return None, None

if __name__ == "__main__":
    # token = "3a68309b0d3ec794728c30caacecee9be2be07f4"
    drive_link = "https://drive.google.com/file/d/1jkz7S6vswVSQX6_yWFzR9VnLN1pA2rah/view?usp=sharing"

    PhishingLinkGenerator().run(drive_link)
