// src/components/Notes.js
import React, { useState, useEffect } from "react";
import { useSession } from "../contexts/SessionContext";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import apiClient from "../api";
import { jwtDecode } from "jwt-decode";
import "./Notes.css";

const isMobile = () => /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

function Notes() {
  const { session, setSession } = useSession();
  const navigate = useNavigate();
  const [notes, setNotes] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [showSidebar, setShowSidebar] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [editingNote, setEditingNote] = useState(null);

  useEffect(() => {
    if (!session?.token) {
      navigate("/login");
      return;
    }
    fetchNotes();
  }, [session, navigate]);

  const fetchNotes = async () => {
    try {
      const response = await apiClient.get("/auth/notes", {
        headers: { Authorization: `Bearer ${session.token}` },
      });
      setNotes(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error("Fetch notes error:", error.response?.data || error.message);
      toast.error("Failed to fetch notes");
      if (error.response?.status === 401) {
        setSession(null);
        navigate("/login");
      }
    }
  };

  const handleSaveNote = async (e) => {
    e.preventDefault();
    if (!title || !content) {
      toast.error("Title and content are required");
      return;
    }
    try {
      const noteData = { title, content };
      let response;
      if (editingNote && editingNote.id) {
        response = await apiClient.put(`/auth/notes/${editingNote.id}`, noteData, {
          headers: { Authorization: `Bearer ${session.token}` },
        });
        setNotes(notes.map((note) => (note.id === editingNote.id ? response.data : note)));
        toast.success("Note updated successfully");
      } else {
        response = await apiClient.post("/auth/notes", noteData, {
          headers: { Authorization: `Bearer ${session.token}` },
        });
        setNotes([...notes, response.data]);
        toast.success("Note created successfully");
      }
      setTitle("");
      setContent("");
      setEditingNote(null);
      setShowModal(false);
      await fetchNotes();
    } catch (error) {
      console.error("Save/Update error:", error.response?.data || error.message);
      toast.error("Failed to save/update note: " + (error.response?.data?.error || error.message));
      if (error.response?.status === 401) {
        setSession(null);
        navigate("/login");
      }
    }
  };

  const handleEdit = (note) => {
    if (!note || !note.id) {
      toast.error("Invalid note selected for editing");
      return;
    }
    setEditingNote(note);
    setTitle(note.title || "");
    setContent(note.content || "");
    setShowModal(true);
  };

  const handleDelete = async (id) => {
    if (!id) {
      toast.error("Invalid note ID");
      return;
    }
    try {
      await apiClient.delete(`/auth/notes/${id}`, {
        headers: { Authorization: `Bearer ${session.token}` },
      });
      setNotes(notes.filter((note) => note.id !== id));
      toast.success("Note deleted successfully");
      await fetchNotes();
    } catch (error) {
      console.error("Delete error:", error.response?.data || error.message);
      toast.error("Failed to delete note: " + (error.response?.data?.error || error.message));
      if (error.response?.status === 401) {
        setSession(null);
        navigate("/login");
      }
    }
  };

  const handleLogout = () => {
    setSession(null);
    navigate("/login");
  };

  const handleSearch = (e) => {
    setSearchQuery(e.target.value);
  };

  const filteredNotes = notes.filter(
    (note) =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const toggleSidebar = () => setShowSidebar(!showSidebar);

  const email = session?.token ? jwtDecode(session.token).sub : "Unknown";

  return (
    <div className="notes-container">
      <nav className="notes-navbar">
        {isMobile() && (
          <button className="sidebar-toggle" onClick={toggleSidebar}>
            ☰
          </button>
        )}
        <h1 className="navbar-title">Notes App</h1>
        <div className="navbar-actions">
          <input
            type="text"
            placeholder="Search notes..."
            value={searchQuery}
            onChange={handleSearch}
            className="search-bar"
          />
          {isMobile() && <span className="user-email">{email}</span>}
          {!isMobile() && (
            <button onClick={handleLogout} className="logout-button">Logout</button>
          )}
        </div>
      </nav>

      {isMobile() && (
        <div className={`sidebar ${showSidebar ? "open" : ""}`}>
          <button className="sidebar-close" onClick={toggleSidebar}>
            ✕
          </button>
          <button onClick={() => navigate("/scan-qr")} className="sidebar-button scan-qr-button">
            Scan QR
          </button>
          <button onClick={handleLogout} className="sidebar-button logout-button">
            Logout
          </button>
        </div>
      )}

      <div className="notes-content">
        {filteredNotes.length > 0 ? (
          filteredNotes.map((note) => (
            <div key={note.id} className="note-card">
              <h3 className="note-card-title">{note.title}</h3>
              <p className="note-card-content">{note.content}</p>
              <div className="note-actions">
                <button onClick={() => handleEdit(note)} className="edit-button">Edit</button>
                <button onClick={() => handleDelete(note.id)} className="delete-button">Delete</button>
              </div>
            </div>
          ))
        ) : (
          <p className="no-notes">No notes available</p>
        )}
      </div>

      <button className="add-note-button" onClick={() => setShowModal(true)}>+</button>

      {showModal && (
        <div className="modal-overlay">
          <div className="modal">
            <h2>{editingNote ? "Edit Note" : "Add Note"}</h2>
            <form onSubmit={handleSaveNote}>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Note Title"
                className="modal-input"
                required
              />
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Note Content"
                className="modal-textarea"
                required
              />
              <div className="modal-actions">
                <button type="submit" className="save-button">
                  {editingNote ? "Update" : "Save"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowModal(false);
                    setTitle("");
                    setContent("");
                    setEditingNote(null);
                  }}
                  className="cancel-button"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Notes;