// src/App.js
import React from "react";
import { BrowserRouter as Router, Route, Routes, useNavigate, useLocation } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Register from "./components/Register";
import Login from "./components/Login";
import ScanQR from "./components/ScanQR";
import { SessionProvider } from "./contexts/SessionContext";
import QRLogin from "./components/QRLogin";
import Notes from "./components/Notes";

const isMobile = () => /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

function AppWrapper() {
  const location = useLocation();
  const navigate = useNavigate();
  const mobile = isMobile();

  React.useEffect(() => {
    const session = JSON.parse(localStorage.getItem("session"));
    const currentPath = location.pathname;

    // Define device-specific and common routes
    const mobileOnlyRoutes = ["/register", "/login", "/scan-qr"];
    const laptopOnlyRoutes = ["/qr-login"];
    const commonRoutes = ["/"];

    // If no session, redirect to appropriate login page
    if (!session) {
      if (mobile && !["/login", "/register"].includes(currentPath)) {
        navigate("/login");
        return;
      } else if (!mobile && currentPath !== "/qr-login") {
        navigate("/qr-login");
        return;
      }
    }
    

    // Restrict mobile users from laptop-only routes
    if (mobile && laptopOnlyRoutes.includes(currentPath)) {
      navigate("/"); // Redirect to home if authenticated
      return;
    }

    // Restrict laptop users from mobile-only routes
    if (!mobile && mobileOnlyRoutes.includes(currentPath)) {
      navigate("/"); // Redirect to home if authenticated
      return;
    }

    // Allow common routes for both if authenticated
    if (!commonRoutes.includes(currentPath) && !mobileOnlyRoutes.includes(currentPath) && !laptopOnlyRoutes.includes(currentPath)) {
      navigate("/"); // Redirect to home for unknown routes
    }
  }, [location, navigate]);

  return (
    <div className="App">
      <ToastContainer
        position="bottom-left"
        autoClose={3000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
      <Routes>
        <Route path="/" element={<Notes />} />
        <Route path="/register" element={<Register />} />
        <Route path="/login" element={<Login />} />
        <Route path="/scan-qr" element={<ScanQR />} />
        <Route path="/qr-login" element={<QRLogin />} />
      </Routes>
    </div>
  );
}

function App() {
  return (
    <Router>
      <SessionProvider>
        <AppWrapper />
      </SessionProvider>
    </Router>
  );
}

export default App;