import requests
import zipfile
import io
import os

def download_and_extract_zip(url, extract_path="."):
    """
    Downloads a zip file from a given URL and extracts its contents.

    Args:
        url (str): The URL of the zip file.
        extract_path (str): The directory where the contents should be extracted.
                            Defaults to the current directory.
    """
    try:
        print(f"Downloading zip file from: {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status() # Raise an exception for bad status codes

        # Create a BytesIO object to hold the downloaded zip content in memory
        zip_content = io.BytesIO(response.content)

        print(f"Extracting zip file to: {os.path.abspath(extract_path)}")
        with zipfile.ZipFile(zip_content, 'r') as zip_ref:
            zip_ref.extractall(extract_path)

        print("Zip file downloaded and extracted successfully.")

    except requests.exceptions.RequestException as e:
        print(f"Error downloading the file: {e}")
    except zipfile.BadZipFile as e:
        print(f"Error: Invalid zip file. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Example usage:
if __name__ == "__main__":
    # Replace with the actual URL of your zip file
    zip_url = "https://example.com/path/to/your_file.zip"
    
    # Replace with your desired extraction directory
    destination_directory = "downloaded_content" 

    download_and_extract_zip(zip_url, destination_directory)