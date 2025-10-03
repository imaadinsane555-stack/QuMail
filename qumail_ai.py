"""
qumail_ai.py — Lightweight offline AI helpers for QuMail

Features:
- summarize_text(text): quick extractive summarizer (first sentences)
- detect_spam(text): keyword-based spam detector
- text_to_speech(text): offline TTS with pyttsx3 if installed, else fallback
- speech_to_text(duration=5): offline STT with vosk if installed, else fallback prompt
"""

import re, threading
from typing import List

# ---------------- Summarizer ----------------
def summarize_text(text: str, max_sentences: int = 2) -> str:
    """Return first 1–2 meaningful sentences as summary."""
    if not text:
        return ""
    s = re.sub(r'\s+', ' ', text).strip()
    sentences = re.split(r'(?<=[.!?])\s+', s)
    sentences = [sent.strip() for sent in sentences if len(sent.strip()) > 20]
    if not sentences:
        return s[:400] + ("…" if len(s) > 400 else "")
    return " ".join(sentences[:max_sentences])

# ---------------- Spam Detector ----------------
_SPAM_KEYWORDS = [
    "prize", "winner", "congratulations", "free", "click here",
    "urgent", "act now", "limited time", "buy now", "credit card",
    "lottery", "claim your", "deposit"
]

def detect_spam(text: str) -> bool:
    """Simple keyword-based spam detection."""
    if not text:
        return False
    t = text.lower()
    for kw in _SPAM_KEYWORDS:
        if kw in t:
            return True
    if t.count("!") >= 3:
        return True
    return False

# ---------------- Text To Speech ----------------
def _try_import_pyttsx3():
    try:
        import pyttsx3
        return pyttsx3
    except Exception:
        return None

_pyttsx3 = _try_import_pyttsx3()

def _speak_with_pyttsx3(text: str):
    engine = _pyttsx3.init()
    try:
        rate = engine.getProperty("rate")
        engine.setProperty("rate", max(120, rate - 20))
    except Exception:
        pass
    engine.say(text)
    engine.runAndWait()
    try:
        engine.stop()
    except Exception:
        pass

def text_to_speech(text: str):
    """Speaks text aloud if pyttsx3 is installed; else prints fallback."""
    if not text:
        return
    def worker():
        if _pyttsx3:
            try:
                _speak_with_pyttsx3(text)
                return
            except Exception:
                pass
        preview = text if len(text) < 200 else text[:200] + "…"
        print("[TTS fallback]", preview)
    threading.Thread(target=worker, daemon=True).start()

# ---------------- Speech To Text ----------------
def _try_import_vosk():
    try:
        import vosk
        return vosk
    except Exception:
        return None

_vosk = _try_import_vosk()

def speech_to_text(duration: int = 5) -> str:
    """
    Offline STT with vosk if installed, else fallback dialog.
    Returns recognized text or typed fallback.
    """
    if _vosk:
        try:
            return _speech_with_vosk(duration)
        except Exception as e:
            print("[STT vosk failed]", e)
    return _speech_fallback_prompt()

def _speech_with_vosk(duration: int) -> str:
    import os, json, queue, sys, time
    from vosk import Model, KaldiRecognizer
    import sounddevice as sd

    model_path = os.getenv("VOSK_MODEL_PATH", "model")
    if not os.path.exists(model_path):
        raise RuntimeError(f"Vosk model not found at {model_path}")
    model = Model(model_path)
    samplerate = 16000
    rec = KaldiRecognizer(model, samplerate)
    q = queue.Queue()

    def callback(indata, frames, time_info, status):
        if status:
            print("Sounddevice:", status, file=sys.stderr)
        q.put(bytes(indata))

    with sd.RawInputStream(samplerate=samplerate, blocksize=8000,
                           dtype='int16', channels=1, callback=callback):
        print(f"[Recording {duration}s]")
        t_end = time.time() + duration
        results = []
        while time.time() < t_end:
            data = q.get()
            if rec.AcceptWaveform(data):
                results.append(json.loads(rec.Result()).get("text", ""))
        results.append(json.loads(rec.FinalResult()).get("text", ""))
    return " ".join([r for r in results if r])

def _speech_fallback_prompt() -> str:
    import tkinter as tk
    from tkinter import simpledialog
    root = tk.Tk()
    root.withdraw()
    res = simpledialog.askstring("Dictate (fallback)",
        "Voice input unavailable. Type your dictation here:")
    try:
        root.destroy()
    except Exception:
        pass
    return res or ""

# ---------------- Capabilities ----------------
def capabilities() -> dict:
    return {
        "tts_offline": bool(_pyttsx3),
        "stt_offline_vosk": bool(_vosk),
        "summarizer": "lightweight",
        "spam_detector": "keywords"
    }

if __name__ == "__main__":
    print("Capabilities:", capabilities())
    sample = "Congratulations! You have won a free prize. Act now!"
    print("Summary:", summarize_text(sample))
    print("Spam?", detect_spam(sample))
    text_to_speech("Hello from QuMail lightweight AI.")
