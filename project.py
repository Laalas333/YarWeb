from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

IPFS_API_URL = 'http://127.0.0.1:5001/api/v0/'  # Default IPFS API URL

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    try:
        files = {'file': (file.filename, file.read())}
        response = requests.post(IPFS_API_URL + 'add', files=files)
        response.raise_for_status()  # Raises an HTTPError if the response was an error

       ipfs_hash = response.json()["Hash"]
        ipfs_url = f'https://ipfs.io/ipfs/{ipfs_hash}'
        
        result = {"message": "File uploaded", "IPFSHash": ipfs_hash, "URL": ipfs_url}
        app.logger.info(f'Response: {result}')  # Log the response
        return jsonify(result), 200
    except requests.exceptions.RequestException as e:
        # Specific info for request exceptions
        app.logger.error(f'Request error: {e}')
        return jsonify({"message": "Failed to communicate with IPFS", "error": str(e)}), 500
    except Exception as e:
        # General exception error
        app.logger.error(f'Unexpected error: {e}')
        return jsonify({"message": "An internal error occurred", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
