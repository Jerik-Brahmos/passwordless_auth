import React, { useState } from "react";
import { QrReader } from "react-qr-reader";
import { useSession } from "../contexts/SessionContext";
import { encryptMessage, computeSharedSecret, generateKeyPair } from "../cryptoUtils";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import apiClient from "../api"; // ✅ Replaced axios with apiClient
import "./MobileLogin.css";

function MobileLogin() {
  const [scanning, setScanning] = useState(false);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const { session, setSession } = useSession();

  const handleScan = async (data) => {
    if (data) {
      setScanning(false);
      setLoading(true);
      try {
        const qrToken = data;

        const detailsResponse = await apiClient.post("/auth/qr-details", { qrToken });
        const { serverPublicKey, challenge, email } = detailsResponse.data;

        const { privateKey, publicKey } = generateKeyPair();
        const sharedSecret = computeSharedSecret(privateKey, serverPublicKey);
        const encryptedChallenge = encryptMessage(challenge, sharedSecret); // Assuming you meant to encrypt using sharedSecret

        const loginResponse = await apiClient.post("/auth/qr-login", {
          qrToken,
          encryptedChallenge,
          userPublicKey: publicKey,
          deviceName: "Mobile",
        });

        setSession({ token: loginResponse.data.token, deviceId: loginResponse.data.deviceId });
        toast.success("Mobile login successful!");
        setMessage("Logged in successfully!");
      } catch (err) {
        toast.error("Mobile login failed: " + (err.response?.data?.error || err.message));
        setMessage("Login failed.");
      } finally {
        setLoading(false);
      }
    }
  };

  const handleError = (err) => {
    console.error(err);
    toast.error("Failed to scan QR code.");
    setScanning(false);
  };

  const isLoggedIn = !!session?.token;

  return (
    <div className="mobile-login-container">
      <h2 className="mobile-login-title">Mobile Login</h2>
      <div className="mobile-form-container">
        {!isLoggedIn && (
          <>
            {!scanning && (
              <button
                className={`scan-button ${loading ? "loading" : ""}`}
                onClick={() => setScanning(true)}
                disabled={loading}
              >
                {loading ? "Processing..." : "Scan QR Code"}
              </button>
            )}
            {scanning && (
              <div className="qr-scanner">
                <QrReader
                  delay={300}
                  onError={handleError}
                  onScan={handleScan}
                  style={{ width: "100%", maxWidth: "300px" }}
                />
                <button
                  className="cancel-button"
                  onClick={() => setScanning(false)}
                >
                  Cancel
                </button>
              </div>
            )}
          </>
        )}
        <p className="mobile-status-message">{message}</p>
        {isLoggedIn && (
          <p className="mobile-status-message">You are logged in! Device ID: {session.deviceId}</p>
        )}
      </div>
    </div>
  );
}

export default MobileLogin;
