// src/components/Login.js
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useSession } from "../contexts/SessionContext";
import { generateECDSAKeyPair, signChallenge, storePrivateKey, retrievePrivateKey } from "../cryptoUtils";
import { toast } from "react-toastify";
import "./Login.css";
import apiClient from "../api";

function Login() {
  const [email, setEmail] = useState("");
  const { setSession } = useSession();
  const navigate = useNavigate();

  const handleLogin = async () => {
    if (!email) {
      toast.error("Please enter an email.");
      return;
    }

    try {
      let privateKey = await retrievePrivateKey(email);
      if (!privateKey) {
        console.log("No private key found for", email, ". Generating new key pair.");
        const { privateKey: newPrivateKey, publicKey } = await generateECDSAKeyPair();
        privateKey = newPrivateKey;
        await storePrivateKey(privateKey, email);
        await apiClient.post("/auth/register", { email, publicKey });
        toast.info("New user registered. Please try logging in again.");
        return;
      }

      const loginResponse = await apiClient.post("/auth/login", {
        email,
        deviceName: "Mobile",
      }, { timeout: 10000 });
      const { challenge } = loginResponse.data;

      if (!challenge) {
        throw new Error("No challenge received from server.");
      }

      const signature = await signChallenge(privateKey, challenge);
      if (!signature) {
        throw new Error("Signature generation failed.");
      }

      const verifyResponse = await apiClient.post("/auth/verify", {
        email,
        signature,
        deviceName: "Mobile",
      }, { timeout: 10000 });
      setSession({ token: verifyResponse.data.token, deviceId: verifyResponse.data.deviceId });
      toast.success("Mobile login successful!");
      navigate("/"); // Redirect to notes (home page)
    } catch (error) {
      console.error("Login error:", error.message, error.response?.data);
      toast.error("Login failed: " + (error.response?.data?.error || error.message));
    }
  };

  return (
    <div className="login-container">
      <div className="login-form">
        <input
          type="email"
          placeholder="Enter email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="login-input"
        />
        <button onClick={handleLogin} className="login-button">Login</button>
  
        {/* Info message */}
        <div className="register-info">
          Don't have an account?{" "}
          <span className="register-link" onClick={() => navigate("/register")}>
            Create one
          </span>
        </div>
      </div>
    </div>
  );
  
}

export default Login;