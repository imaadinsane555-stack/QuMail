"""
QuMail GUI — Polished Final Version
- Live IMAP inbox fetching & decryption
- Compose with 4 security levels
- Multi-account add/switch/remove
- Inline Preferences (KM URL + Theme toggle)
- Light theme default, dark toggle
- Sidebar with icons and colors
- AI toolbar: Summarize, Spam check, Read aloud, Dictate
"""

import os, json, base64, imaplib, smtplib, email, threading, time
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from qumail_crypto import (
    generate_kem_keypair, register_identity, encrypt_message, decrypt_message_for_recipient
)
from qumail_ai import summarize_text, detect_spam, text_to_speech, speech_to_text

# ---------------- Config ----------------
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".qumail")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
KM_DEFAULT = "http://127.0.0.1:5000"

if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {"accounts": {}, "prefs": {"theme":"light", "km_url": KM_DEFAULT}}
    try:
        return json.load(open(CONFIG_PATH,"r"))
    except Exception:
        return {"accounts": {}, "prefs": {"theme":"light", "km_url": KM_DEFAULT}}

def save_config(cfg):
    json.dump(cfg, open(CONFIG_PATH,"w"), indent=2)

cfg = load_config()

# ---------------- Utils ----------------
def run_in_thread(fn, *args, **kwargs):
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()

def load_icon(name, size=18):
    # Simple fallback: text emoji if no image
    icons = {
        "inbox": "📥", "compose": "✉️", "accounts": "👤",
        "prefs": "⚙️", "logout": "🚪"
    }
    return icons.get(name,"?")

# ---------------- Login / Register ----------------
class LoginWindow(ctk.CTk):

    def __init__(self, on_success):
        super().__init__()
        self.title("QuMail Login")
        self.geometry("400x300")
        self.on_success = on_success
        self.build_ui()

    def build_ui(self):
        self.tab = ctk.CTkTabview(self)
        self.tab.pack(fill="both", expand=True, padx=10, pady=10)
        self.login_tab = self.tab.add("Login")
        self.reg_tab = self.tab.add("Register")

        # Login
        self.login_var = tk.StringVar(value="")
        accs = list(cfg["accounts"].keys())
        self.login_menu = ctk.CTkOptionMenu(self.login_tab, values=accs, variable=self.login_var)
        self.login_menu.pack(pady=10)
        ctk.CTkButton(self.login_tab, text="Login", command=self.do_login).pack(pady=5)

        # Register
        DOMAIN_PRESETS = {
        "gmail.com":   {"imap": "imap.gmail.com", "smtp": "smtp.gmail.com"},
        "outlook.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
        "hotmail.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
        "live.com":    {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
        "office365.com": {"imap": "outlook.office365.com", "smtp": "smtp.office365.com"},
        "yahoo.com":   {"imap": "imap.mail.yahoo.com", "smtp": "smtp.mail.yahoo.com"},
        "zoho.com":    {"imap": "imap.zoho.com", "smtp": "smtp.zoho.com"}
        }
        self.DOMAIN_PRESETS = DOMAIN_PRESETS  # Save as instance variable

        self.reg_email = ctk.CTkEntry(self.reg_tab, placeholder_text="Email")
        self.reg_email.bind("<FocusOut>", self.autofill_from_email)
        self.reg_email.pack(pady=5, fill="x", padx=20)

        self.reg_imap = ctk.CTkEntry(self.reg_tab, placeholder_text="IMAP host")
        self.reg_smtp = ctk.CTkEntry(self.reg_tab, placeholder_text="SMTP host")
        self.reg_pwd  = ctk.CTkEntry(self.reg_tab, placeholder_text="Password", show="*")
        for w in [self.reg_imap, self.reg_smtp, self.reg_pwd]:
            w.pack(pady=5, fill="x", padx=20)

        ctk.CTkButton(self.reg_tab, text="Register", command=self.do_register).pack(pady=10)

    def autofill_from_email(self, event=None):
        email_addr = self.reg_email.get().strip().lower()
        if "@" not in email_addr:
            return
        domain = email_addr.split("@")[-1]
        preset = self.DOMAIN_PRESETS.get(domain)
        if preset:
            self.reg_imap.delete(0,"end"); self.reg_imap.insert(0,preset["imap"])
            self.reg_smtp.delete(0,"end"); self.reg_smtp.insert(0,preset["smtp"])
            self.reg_smtp.delete(0,"end"); self.reg_smtp.insert(0,preset["smtp"])

            self.reg_email = ctk.CTkEntry(self.reg_tab, placeholder_text="Email")
            self.reg_imap = ctk.CTkEntry(self.reg_tab, placeholder_text="IMAP host")
            self.reg_smtp = ctk.CTkEntry(self.reg_tab, placeholder_text="SMTP host")
            self.reg_pwd  = ctk.CTkEntry(self.reg_tab, placeholder_text="Password", show="*")
            for w in [self.reg_email,self.reg_imap,self.reg_smtp,self.reg_pwd]:
                w.pack(pady=5, fill="x", padx=20)
            ctk.CTkButton(self.reg_tab, text="Register", command=self.do_register).pack(pady=10)

    def do_login(self):
        email_addr = self.login_var.get()
        if email_addr not in cfg["accounts"]:
            messagebox.showerror("QuMail","Account not registered. Use Register tab.")
            return
        self.destroy()
        self.on_success(email_addr)

    def do_register(self):
        email_addr = self.reg_email.get().strip()
        imap_host = self.reg_imap.get().strip()
        smtp_host = self.reg_smtp.get().strip()
        pwd = self.reg_pwd.get().strip()
        if not (email_addr and imap_host and smtp_host and pwd):
            messagebox.showerror("QuMail","Fill all fields.")
            return
        pub, priv = generate_kem_keypair()
        acc = {"imap":imap_host,"smtp":smtp_host,"password":pwd,"pub":pub,"priv":priv}
        cfg["accounts"][email_addr] = acc
        save_config(cfg)
        try:
            register_identity(cfg["prefs"]["km_url"], email_addr, pub)
        except Exception as e:
            messagebox.showwarning("QuMail",f"KM register failed: {e}")
        self.destroy()
        self.on_success(email_addr)

# ---------------- Main App ----------------
class QuMailApp(ctk.CTk):
    def __init__(self, active_account):
        super().__init__()
        theme = cfg["prefs"].get("theme","light")
        ctk.set_appearance_mode(theme)
        self.title("QuMail")
        self.geometry("1000x600")
        self.active_account = active_account

        self.sidebar = ctk.CTkFrame(self,width=180,fg_color="#f5f5f5" if theme=="light" else "#2b2b2b")
        self.sidebar.pack(side="left", fill="y")
        self.content = ctk.CTkFrame(self)
        self.content.pack(side="right", fill="both", expand=True)

        for label,icon,cmd in [
            ("Inbox","inbox",self.show_inbox),
            ("Compose","compose",self.show_compose),
            ("Accounts","accounts",self.show_accounts),
            ("Preferences","prefs",self.show_prefs),
            ("Logout","logout",self.do_logout)]:
            ctk.CTkButton(self.sidebar,text=f"{load_icon(icon)} {label}",command=cmd).pack(pady=5,fill="x")

        self.show_inbox()

    # ----- Inbox -----
    def show_inbox(self):
        for w in self.content.winfo_children(): w.destroy()
        split = tk.PanedWindow(self.content,orient=tk.HORIZONTAL)
        split.pack(fill="both",expand=True)

        self.msg_list = tk.Listbox(split,background="#fff")
        split.add(self.msg_list,width=300)
        self.msg_detail = tk.Text(split,wrap="word")
        split.add(self.msg_detail)

        tb = ctk.CTkFrame(self.content); tb.pack(fill="x")
        ctk.CTkButton(tb,text="Summarize",command=self.ai_summarize).pack(side="left",padx=5)
        ctk.CTkButton(tb,text="Spam?",command=self.ai_spam).pack(side="left",padx=5)
        ctk.CTkButton(tb,text="Read Aloud",command=self.ai_tts).pack(side="left",padx=5)

        run_in_thread(self.fetch_inbox)

    def fetch_inbox(self):
        self.msg_list.delete(0,"end")
        acc = cfg["accounts"][self.active_account]
        try:
            imap = imaplib.IMAP4_SSL(acc["imap"])
            imap.login(self.active_account, acc["password"])
            imap.select("inbox")
            typ, data = imap.search(None, "ALL")
            ids = data[0].split()[-10:]  # last 10 msgs
            for i,uid in enumerate(reversed(ids)):
                typ, msg_data = imap.fetch(uid,"(RFC822)")
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw)
                subj = msg.get("Subject","(no subject)")
                self.msg_list.insert("end", subj)
                # alternating row colors
                self.msg_list.itemconfig(i, bg="#fafafa" if i%2==0 else "#eaeaea")
            imap.close(); imap.logout()
            self.msg_list.bind("<<ListboxSelect>>", self.show_msg)
        except Exception as e:
            messagebox.showerror("QuMail",f"Inbox fetch failed: {e}")

    def show_msg(self,event):
        sel = self.msg_list.curselection()
        if not sel: return
        idx = sel[0]
        acc = cfg["accounts"][self.active_account]
        try:
            imap = imaplib.IMAP4_SSL(acc["imap"])
            imap.login(self.active_account, acc["password"])
            imap.select("inbox")
            typ, data = imap.search(None, "ALL")
            ids = data[0].split()[-10:]
            uid = list(reversed(ids))[idx]
            typ, msg_data = imap.fetch(uid,"(RFC822)")
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            payload = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type()=="text/plain":
                        payload = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                payload = msg.get_payload(decode=True).decode(errors="ignore")

            try:
                env = json.loads(payload)
                plain,_ = decrypt_message_for_recipient(env,self.active_account,acc["priv"],cfg["prefs"]["km_url"])
                self.msg_detail.delete("1.0","end")
                self.msg_detail.insert("end",plain.decode(errors="ignore"))
            except Exception:
                self.msg_detail.delete("1.0","end")
                self.msg_detail.insert("end",payload)
            imap.close(); imap.logout()
        except Exception as e:
            messagebox.showerror("QuMail",f"Show message failed: {e}")

    def ai_summarize(self):
        txt = self.msg_detail.get("1.0","end").strip()
        sm = summarize_text(txt)
        messagebox.showinfo("Summary",sm)

    def ai_spam(self):
        txt = self.msg_detail.get("1.0","end").strip()
        messagebox.showinfo("Spam Detector","Spam ✅" if detect_spam(txt) else "Not spam")

    def ai_tts(self):
        text_to_speech(self.msg_detail.get("1.0","end").strip())

    # ----- Compose -----
# ----- Compose -----
    def show_compose(self):
        for w in self.content.winfo_children(): 
            w.destroy()

        f = ctk.CTkFrame(self.content)
        f.pack(fill="both", expand=True, padx=10, pady=10)

    # FROM (read-only)
        self.from_var = tk.StringVar(value=self.active_account)
        from_entry = ctk.CTkEntry(f, textvariable=self.from_var, state="readonly")
        ctk.CTkLabel(f, text="From:").pack(anchor="w")
        from_entry.pack(fill="x", pady=5)

# TO
        ctk.CTkLabel(f, text="To:").pack(anchor="w")
        self.to_entry = ctk.CTkEntry(f)
        self.to_entry.pack(fill="x", pady=5)

# SUBJECT
        ctk.CTkLabel(f, text="Subject:").pack(anchor="w")
        self.sub_entry = ctk.CTkEntry(f)
        self.sub_entry.pack(fill="x", pady=5)

    # BODY
        ctk.CTkLabel(f, text="Message:").pack(anchor="w")
        self.body = tk.Text(f, height=15)
        self.body.pack(fill="both", expand=True, pady=5)


    # SECURITY LEVEL
        self.sec_level_var = tk.StringVar(value="2 - QKD-AES")
        ctk.CTkOptionMenu(f,
            values=["1 - OTP","2 - QKD-AES","3 - PQC-Kyber","4 - AES Fallback"],
            variable=self.sec_level_var).pack(pady=5)

    # Buttons
        btns = ctk.CTkFrame(f)
        btns.pack(fill="x")
        ctk.CTkButton(btns, text="Send", command=self.send_mail).pack(side="right", padx=5)
        ctk.CTkButton(btns, text="Dictate", command=self.do_dictate).pack(side="right", padx=5)


    def do_dictate(self):
        res = speech_to_text()
        if res: self.body.insert("end",res)

    def send_mail(self):
        frm = self.active_account
        to = self.to_var.get().strip().split(",")
        sub = self.sub_var.get().strip()
        body = self.body.get("1.0","end").encode()
        acc = cfg["accounts"][frm]
        try:
            env = encrypt_message(frm, acc["priv"], to, body, [], cfg["prefs"]["km_url"],
                                  security_level=int(self.sec_level_var.get()[0]))
            msg = MIMEMultipart()
            msg["From"], msg["To"], msg["Subject"] = frm, ",".join(to), sub
            msg.attach(MIMEText(json.dumps(env),"plain"))
            s = smtplib.SMTP(acc["smtp"],587); s.starttls()
            s.login(frm,acc["password"])
            s.sendmail(frm,to,msg.as_string()); s.quit()
            messagebox.showinfo("QuMail","Mail sent.")
        except Exception as e:
            messagebox.showerror("QuMail",f"Send failed: {e}")

    # ----- Accounts -----
    def show_accounts(self):
        for w in self.content.winfo_children(): w.destroy()
        f = ctk.CTkFrame(self.content); f.pack(fill="both",expand=True,padx=10,pady=10)
        tk.Label(f,text="Accounts:").pack()
        for email_addr in cfg["accounts"].keys():
            row = ctk.CTkFrame(f); row.pack(fill="x",pady=2)
            ctk.CTkLabel(row,text=email_addr).pack(side="left")
            ctk.CTkButton(row,text="Switch",command=lambda e=email_addr:self.switch_account(e)).pack(side="right")
            ctk.CTkButton(row,text="Remove",command=lambda e=email_addr:self.remove_account(e)).pack(side="right")

    def switch_account(self,email_addr):
        self.active_account = email_addr
        messagebox.showinfo("QuMail",f"Switched to {email_addr}")

    def remove_account(self,email_addr):
        if email_addr in cfg["accounts"]:
            del cfg["accounts"][email_addr]
            save_config(cfg)
            messagebox.showinfo("QuMail","Removed account.")

    # ----- Preferences -----
    def show_prefs(self):
        for w in self.content.winfo_children(): w.destroy()
        f = ctk.CTkFrame(self.content); f.pack(fill="both",expand=True,padx=10,pady=10)
        theme_var = tk.StringVar(value=cfg["prefs"].get("theme","light"))
        km_var = tk.StringVar(value=cfg["prefs"].get("km_url",KM_DEFAULT))

        ctk.CTkLabel(f,text="Theme:").pack()
        ctk.CTkOptionMenu(f,values=["light","dark"],variable=theme_var).pack()
        ctk.CTkLabel(f,text="KM URL:").pack()
        ctk.CTkEntry(f,textvariable=km_var).pack(fill="x")

        def save_prefs():
            cfg["prefs"]["theme"] = theme_var.get()
            cfg["prefs"]["km_url"] = km_var.get()
            save_config(cfg)
            ctk.set_appearance_mode(theme_var.get())
            messagebox.showinfo("QuMail","Preferences saved.")

        ctk.CTkButton(f,text="Save",command=save_prefs).pack(pady=10)

    # ----- Logout -----
    def do_logout(self):
        self.destroy()
        LoginWindow(on_success=lambda acc: QuMailApp(acc).mainloop()).mainloop()

# ---------------- Main ----------------
def main():
    LoginWindow(on_success=lambda acc: QuMailApp(acc).mainloop()).mainloop()

if __name__ == "__main__":
    main()
