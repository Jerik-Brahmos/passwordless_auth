import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { generateECDSAKeyPair, storePrivateKey } from "../cryptoUtils";
import apiClient from "../api";
import { GoogleLogin } from "@react-oauth/google";
import { jwtDecode } from 'jwt-decode';

import "./Register.css";

function Register() {
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleGoogleRegister = async (credentialResponse) => {
    console.log("Google response:", credentialResponse);
    setLoading(true);
    setMessage("");

    try {
      const idToken = credentialResponse.credential;

      if (!idToken) {
        throw new Error("No ID token received from Google");
      }

      // Decode the ID token using jwtDecode
      const userInfo = jwtDecode(idToken);
      const googleEmail = userInfo.email;

      if (!googleEmail) {
        throw new Error("Email not found in Google ID token");
      }

      // Check if email already exists
      const checkResponse = await apiClient.post("/auth/check-email", { email: googleEmail });
      if (checkResponse.data.exists) {
        setMessage("This email is already registered. Please log in.");
        toast.error("This email is already registered. Please log in.");
        setLoading(false);
        return;
      }

      // Generate ECDSA key pair and register
      const { privateKey, publicKey } = await generateECDSAKeyPair();
      await storePrivateKey(privateKey, googleEmail);

      await apiClient.post("/auth/register", { email: googleEmail, publicKey });

      setMessage("Registration successful with Google! You can now log in.");
      toast.success("Registration successful with Google! You can now log in.");
      navigate("/login");
    } catch (error) {
      setMessage("Google registration failed. Please try again.");
      toast.error("Google registration failed: " + (error.message || "Unknown error"));
      console.error("Error details:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="register-container">
      <h2 className="register-title">Create an Account</h2>
      <div className="register-form">
        <p className="info-text">
          Sign up quickly and securely using your Google account. We’ll use your email to create your account and ensure your data is protected with advanced encryption.
        </p>
        <GoogleLogin
          onSuccess={handleGoogleRegister}
          onError={() => {
            setMessage("Google authentication failed. Please try again.");
            toast.error("Google authentication failed.");
            setLoading(false);
          }}
          text="signup_with"
          shape="pill"
          width="200"
          disabled={loading}
          className="google-button"
        />
        {message && (
          <p className={`status-message ${message.includes("failed") || message.includes("already") ? "error" : "success"}`}>
            {message}
          </p>
        )}
        <p className="sign-in-text">
          Already have an account?{" "}
          <span onClick={() => navigate("/login")} className="sign-in-link">
            Sign In
          </span>
        </p>
        <p className="privacy-text">
          Your privacy is important to us. By signing up, you agree to our{" "}
          <a href="/terms" target="_blank" rel="noopener noreferrer" className="privacy-link">
            Terms of Service
          </a>{" "}
          and{" "}
          <a href="/privacy" target="_blank" rel="noopener noreferrer" className="privacy-link">
            Privacy Policy
          </a>. We use Google’s secure authentication to protect your information.
        </p>
      </div>
    </div>
  );
}

export default Register;