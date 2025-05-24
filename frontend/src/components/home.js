// src/components/Home.js
import React from "react";
import { useSession } from "../contexts/SessionContext";
import { useNavigate } from "react-router-dom";
import "./home.css";

function Home() {
  const { session } = useSession();
  const navigate = useNavigate();

  const handleNotesClick = () => {
    navigate("/notes");
  };

  return (
    <div className="home-container">
      <div className="home-form-container">
        <h2 className="home-title">Welcome!</h2>
        <p className="home-message">You are logged in on your laptop.</p>
        <p className="home-device-id">Device ID: {session?.deviceId}</p>
        <button onClick={handleNotesClick} className="notes-button">
          Go to Notes
        </button>
      </div>
    </div>
  );
}

export default Home;