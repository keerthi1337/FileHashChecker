import os
import json
import logging
import requests

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
TEXT_REPORT_FILE = "report.txt"
JSON_REPORT_FILE = "report.json"
LOG_FILE = "hash_checks.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def get_verdict(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return "Potentially malicious"
    elif suspicious > 0:
        return "Suspicious"
    else:
        return "No strong detection shown"


def get_malicious_engines(results):
    malicious_engines = []

    for engine, details in results.items():
        if details.get("category") == "malicious":
            engine_name = details.get("engine_name", engine)
            detection_name = details.get("result", "No name provided")
            malicious_engines.append(f"{engine_name}: {detection_name}")

    return malicious_engines


def save_text_report(details, malicious_engines):
    with open(TEXT_REPORT_FILE, "a", encoding="utf-8") as file:
        file.write("VirusTotal Hash Check Report\n")
        file.write("=" * 40 + "\n")

        for key, value in details.items():
            file.write(f"{key}: {value}\n")

        file.write("Malicious Engines:\n")
        if malicious_engines:
            for engine in malicious_engines:
                file.write(f"- {engine}\n")
        else:
            file.write("- None\n")

        file.write("\n")


def save_json_report(data):
    with open(JSON_REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def main():
    if not API_KEY:
        print("Error: VIRUSTOTAL_API_KEY not found.")
        logging.error("API key not found.")
        return

    file_hash = input("Enter MD5, SHA1, or SHA256 hash: ").strip()

    if len(file_hash) not in [32, 40, 64]:
        print("Invalid hash length. Use MD5, SHA1, or SHA256.")
        logging.warning(f"Invalid hash length entered: {file_hash}")
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            results = attributes.get("last_analysis_results", {})

            md5 = attributes.get("md5", "N/A")
            sha1 = attributes.get("sha1", "N/A")
            sha256 = attributes.get("sha256", "N/A")
            meaningful_name = attributes.get("meaningful_name", "N/A")
            file_type = attributes.get("type_description", "N/A")
            reputation = attributes.get("reputation", "N/A")
            times_submitted = attributes.get("times_submitted", "N/A")

            verdict = get_verdict(stats)
            malicious_engines = get_malicious_engines(results)

            print("\nVirusTotal Result")
            print("-" * 30)
            print("Input Hash:", file_hash)
            print("Meaningful Name:", meaningful_name)
            print("File Type:", file_type)
            print("MD5:", md5)
            print("SHA1:", sha1)
            print("SHA256:", sha256)
            print("Reputation:", reputation)
            print("Times Submitted:", times_submitted)
            print("Malicious:", stats.get("malicious", 0))
            print("Suspicious:", stats.get("suspicious", 0))
            print("Harmless:", stats.get("harmless", 0))
            print("Undetected:", stats.get("undetected", 0))
            print("Verdict:", verdict)

            print("\nMalicious Engines:")
            if malicious_engines:
                for engine in malicious_engines:
                    print("-", engine)
            else:
                print("- None")

            details = {
                "Input Hash": file_hash,
                "Meaningful Name": meaningful_name,
                "File Type": file_type,
                "MD5": md5,
                "SHA1": sha1,
                "SHA256": sha256,
                "Reputation": reputation,
                "Times Submitted": times_submitted,
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
                "Verdict": verdict
            }

            save_text_report(details, malicious_engines)
            save_json_report(data)

            logging.info(f"Hash checked: {file_hash} | Verdict: {verdict}")

            print(f"\nDetailed text report saved to {TEXT_REPORT_FILE}")
            print(f"Raw JSON response saved to {JSON_REPORT_FILE}")
            print(f"Log entry saved to {LOG_FILE}")

        elif response.status_code == 404:
            print("Hash not found in VirusTotal database.")
            logging.warning(f"Hash not found: {file_hash}")

        elif response.status_code == 401:
            print("Unauthorized. Check your API key.")
            logging.error(f"Unauthorized request for hash: {file_hash}")

        else:
            print(f"Error: HTTP {response.status_code}")
            print(response.text)
            logging.error(f"HTTP {response.status_code} for hash: {file_hash}")

    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        logging.error(f"Request failed for hash {file_hash}: {e}")


if __name__ == "__main__":
    main()