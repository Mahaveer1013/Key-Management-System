/*

File: scripts/add-user.js
This script adds 2000 users to the key server by sending POST requests to the API
It uses axios to make HTTP requests and logs the status and response for each request
Make sure to run this script in an environment where axios is installed
Usage: node add-user.js
Ensure the key server is running at the specified URL before executing this script

*/
import axios from 'axios';

const url = "http://127.0.0.1:8000/api/keys"

for(let i = 1; i <= 2000; i++) {  // 1 to 2000
    const payload = {
        user_id: String(i),
        data: `test-data-${i}`
    };

    axios.post(url, payload)
        .then(response => {
            console.log(`[${i}] Status: ${response.status} | Response: ${response.data}`);
        })
        .catch(error => {
            console.error(`[${i}] Failed: ${error.message}`);
        });
}
