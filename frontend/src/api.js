import axios from "axios";

const API_BASE_URL = "https://passwordless-auth-va6v.onrender.com";
// const API_BASE_URL = "http://localhost:8080";

const apiClient = axios.create({
    baseURL: `${API_BASE_URL}/api`,
    headers: {
        "Content-Type": "application/json",
    },
});

export default apiClient;
