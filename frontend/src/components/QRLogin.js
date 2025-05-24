// src/components/QRLogin.js
import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useSession } from "../contexts/SessionContext";
import QRCode from "react-qr-code";
import apiClient from "../api";
import "./QRLogin.css";

function QRLogin() {
  const [qrToken, setQrToken] = useState("");
  const [loading, setLoading] = useState(false);
  const { setSession } = useSession();
  const navigate = useNavigate();

  useEffect(() => {
    handleGenerateQR();
  }, []);

  const handleGenerateQR = async () => {
    setLoading(true);
    try {
      const response = await apiClient.post("/auth/generate-qr", { email: "", token: "" });
      setQrToken(response.data.qrToken);
      console.log("Generated QR Token:", response.data.qrToken); // Log the token

      const interval = setInterval(async () => {
        try {
          const checkResponse = await apiClient.get(`/auth/check-qr-status?qrToken=${response.data.qrToken}`);
          if (checkResponse.data.status === "authenticated") {
            setSession({ token: checkResponse.data.token, deviceId: checkResponse.data.deviceId });
            clearInterval(interval);
            navigate("/");
          }
        } catch (error) {
          console.error("Polling error:", error);
        }
      }, 2000);

      return () => clearInterval(interval);
    } catch (error) {
      console.error("Failed to generate QR:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="qr-login-container">
      <div className="qr-form-container">
        {loading ? (
          <p className="qr-loading">Generating QR...</p>
        ) : qrToken ? (
          <div className="qr-content">
            <h2 className="qr-title">Scan this QR code from your mobile device</h2>
            <QRCode value={qrToken} size={300} className="qr-code" />
          </div>
        ) : (
          <p className="qr-error">Error loading QR code. Please try again.</p>
        )}
      </div>
    </div>
  );
}

export default QRLogin;