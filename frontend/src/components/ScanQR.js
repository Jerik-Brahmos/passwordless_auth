// src/components/ScanQR.js
import React, { useState, useEffect, useRef } from "react";
import { BrowserQRCodeReader } from "@zxing/library";
import { useNavigate } from "react-router-dom";
import { useSession } from "../contexts/SessionContext";
import { toast } from "react-toastify";
import apiClient from "../api";
import "./ScanQR.css";

function ScanQR() {
  const [loading, setLoading] = useState(false);
  const { session } = useSession();
  const navigate = useNavigate();
  const videoRef = useRef(null);
  const codeReader = useRef(new BrowserQRCodeReader());

  useEffect(() => {
    const startScanner = async () => {
      try {
        const videoElement = videoRef.current;
        if (!videoElement) {
          throw new Error("Video element not found");
        }
        await codeReader.current.decodeFromVideoDevice(null, videoElement, (result, error) => {
          if (result && !loading) {
            handleScan(result.getText());
          }
          if (error && !loading) {
            console.warn("QR scan warning:", error.message);
          }
        });
      } catch (err) {
        console.error("Failed to start QR scanner:", err);
        toast.error("Error initializing QR scanner: " + err.message);
      }
    };

    startScanner();

    return () => {
      if (codeReader.current) {
        codeReader.current.reset();
      }
    };
  }, [loading]);

  const handleScan = async (qrToken) => {
    if (!loading && qrToken) {
      setLoading(true);
      try {
        if (!session?.token) {
          throw new Error("No mobile session found. Please log in again.");
        }
        const response = await apiClient.post("/auth/qr-verify", {
          qrToken,
          mobileToken: session.token,
        });
        toast.success("QR verification successful!");
        navigate("/");
      } catch (error) {
        const errorMessage = error.response?.data?.error || error.message || "Internal server error";
        toast.error("Failed to verify QR: " + errorMessage);
        if (error.response?.status === 401 || error.message.includes("session")) {
          navigate("/login"); // Redirect to login if session is invalid
        }
      } finally {
        setLoading(false);
      }
    } else if (!qrToken) {
      toast.error("No QR code detected");
      setLoading(false);
    }
  };

  return (
    <div className="scan-qr-container">
      <div className="scan-qr-form">
        <h2 className="scan-qr-title">Scan QR Code</h2>
        {loading ? (
          <p className="scan-qr-loading">Verifying...</p>
        ) : (
          <video ref={videoRef} style={{ width: "100%", maxWidth: "400px" }} />
        )}
      </div>
    </div>
  );
}

export default ScanQR;