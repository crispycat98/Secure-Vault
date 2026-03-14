"""
Secure Password Vault
=====================
Requirements:  pip install customtkinter cryptography bcrypt

Run:           python login_app_v6.py
DB:            accounts.db  (auto-created next to the script)
               Delete accounts.db whenever the schema changes.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import sqlite3
import random
import time
import string
import os
import bcrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64


# ══════════════════════════════════════════════════════════════════════════════
#  APPEARANCE
# ══════════════════════════════════════════════════════════════════════════════

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

class Theme:
    ACCENT       = "#5C8A72"
    ACCENT_DARK  = "#3E6B55"
    ACCENT_LIGHT = "#7ab898"
    TEXT_MID     = "#94A3B8"
    BORDER       = "#2a2a4a"
    FONT_HEAD    = "Georgia"
    FONT_BODY    = "Helvetica"

    # Pattern panel
    P_BG      = "#0F1117"
    P_CARD    = "#1A1D2E"
    P_BORDER  = "#2E3150"
    P_ACCENT  = "#5C8A72"
    P_TEXT    = "#E2E8F0"
    P_SUBTEXT = "#94A3B8"

    # Vault dashboard
    V_BG      = "#0d1117"
    V_SIDEBAR = "#161b22"
    V_CARD    = "#21262d"
    V_BORDER  = "#30363d"
    V_ACCENT  = "#5C8A72"
    V_TEXT    = "#e6edf3"
    V_SUBTEXT = "#8b949e"
    V_RED     = "#f85149"
    V_GREEN   = "#3fb950"
    V_YELLOW  = "#d29922"


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO
# ══════════════════════════════════════════════════════════════════════════════

class Crypto:

    @staticmethod
    def generate_salt():
        return os.urandom(16).hex()

    @staticmethod
    def derive_key(pattern_sequence, salt_hex):
        password = "-".join(str(i) for i in pattern_sequence).encode()
        salt     = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    @staticmethod
    def encrypt(key, plaintext):
        return Fernet(key).encrypt(plaintext.encode()).decode()

    @staticmethod
    def decrypt(key, ciphertext):
        try:
            return Fernet(key).decrypt(ciphertext.encode()).decode()
        except Exception:
            return None

    @staticmethod
    def generate_password(length=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            pwd = "".join(random.choices(alphabet, k=length))
            if (any(c.islower() for c in pwd)
                    and any(c.isupper() for c in pwd)
                    and any(c.isdigit() for c in pwd)
                    and any(c in "!@#$%^&*" for c in pwd)):
                return pwd

    @staticmethod
    def score_password(pwd):
        score = 0
        if len(pwd) >= 8:  score += 1
        if len(pwd) >= 12: score += 1
        if any(c.isdigit() for c in pwd): score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd): score += 1
        if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd): score += 1
        return score

    @staticmethod
    def generate_recovery_code():
        """
        Returns a 24-char code split into 4 groups of 6, e.g. 'A3KX9Z-BW72PQ-MN4TR8-YC6JD1'.
        Avoids ambiguous chars (0/O, 1/I/L).
        """
        alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
        raw = "".join(random.choices(alphabet, k=24))
        return "-".join(raw[i:i+6] for i in range(0, 24, 6))

    @staticmethod
    def hash_recovery_code(code):
        normalised = code.replace("-", "").upper()
        return bcrypt.hashpw(normalised.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def verify_recovery_code(code, hashed):
        if not hashed:
            return False
        normalised = code.replace("-", "").upper()
        try:
            return bcrypt.checkpw(normalised.encode(), hashed.encode())
        except Exception:
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class SessionManager:
    def __init__(self):
        self._key  = None
        self._user = None

    def open(self, username, key):
        self._user = username
        self._key  = key

    def close(self):
        self._user = None
        self._key  = None

    @property
    def key(self):
        return self._key

    @property
    def username(self):
        return self._user


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════════════

class Database:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.db")

    @classmethod
    def _connect(cls):
        return sqlite3.connect(cls.DB_PATH)

    @classmethod
    def create_tables(cls):
        with cls._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT UNIQUE NOT NULL,
                    password        TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until    REAL    NOT NULL DEFAULT 0
                )''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS user_patterns (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    username         TEXT UNIQUE NOT NULL,
                    grid_colors      TEXT NOT NULL,
                    pattern_sequence TEXT NOT NULL,
                    salt                 TEXT NOT NULL DEFAULT "",
                    recovery_code_hash   TEXT NOT NULL DEFAULT ""
                )''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vault (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    username           TEXT NOT NULL,
                    site               TEXT NOT NULL,
                    site_username      TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    created_at         REAL NOT NULL
                )''')
            for sql in [
                "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE users ADD COLUMN locked_until REAL NOT NULL DEFAULT 0",
                'ALTER TABLE user_patterns ADD COLUMN salt TEXT NOT NULL DEFAULT ""',
                'ALTER TABLE user_patterns ADD COLUMN recovery_code_hash TEXT NOT NULL DEFAULT ""',
            ]:
                try:
                    conn.execute(sql)
                except Exception:
                    pass

    @classmethod
    def insert_user(cls, username, password):
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with cls._connect() as conn:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (username, hashed.decode()))

    @classmethod
    def get_user(cls, username):
        with cls._connect() as conn:
            return conn.execute("SELECT * FROM users WHERE username=?",
                                (username,)).fetchone()

    @classmethod
    def user_exists(cls, username):
        return cls.get_user(username) is not None

    @classmethod
    def get_failed_attempts(cls, username):
        u = cls.get_user(username)
        return u[3] if u else 0

    @classmethod
    def get_locked_until(cls, username):
        u = cls.get_user(username)
        return u[4] if u else 0.0

    @classmethod
    def increment_failed_attempts(cls, username):
        with cls._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=failed_attempts+1 WHERE username=?",
                (username,))

    @classmethod
    def lock_user(cls, username):
        locked_until = time.time() + 24 * 3600
        with cls._connect() as conn:
            conn.execute(
                "UPDATE users SET locked_until=?, failed_attempts=0 WHERE username=?",
                (locked_until, username))
        return locked_until

    @classmethod
    def reset_failed_attempts(cls, username):
        with cls._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
                (username,))

    @classmethod
    def insert_pattern(cls, username, grid_colors, pattern_sequence, salt,
                       recovery_code_hash):
        with cls._connect() as conn:
            conn.execute(
                "INSERT INTO user_patterns "
                "(username, grid_colors, pattern_sequence, salt, recovery_code_hash) "
                "VALUES (?,?,?,?,?)",
                (username,
                 ",".join(grid_colors),
                 ",".join(str(i) for i in pattern_sequence),
                 salt,
                 recovery_code_hash))

    @classmethod
    def get_pattern(cls, username):
        """Returns (grid_colors, sequence, salt, recovery_code_hash) or None."""
        with cls._connect() as conn:
            row = conn.execute(
                "SELECT grid_colors, pattern_sequence, salt, recovery_code_hash "
                "FROM user_patterns WHERE username=?",
                (username,)).fetchone()
        if not row:
            return None
        return (row[0].split(","),
                [int(x) for x in row[1].split(",")],
                row[2],
                row[3])

    @classmethod
    def update_pattern(cls, username, grid_colors, pattern_sequence, salt,
                       recovery_code_hash):
        """Replace pattern + salt after successful recovery. Re-uses existing row."""
        with cls._connect() as conn:
            conn.execute(
                "UPDATE user_patterns "
                "SET grid_colors=?, pattern_sequence=?, salt=?, recovery_code_hash=? "
                "WHERE username=?",
                (",".join(grid_colors),
                 ",".join(str(i) for i in pattern_sequence),
                 salt,
                 recovery_code_hash,
                 username))

    @classmethod
    def reencrypt_vault(cls, username, old_key, new_key):
        entries = cls.get_vault_entries(username)
        # Decrypt everything first — if any entry fails, nothing gets written
        reencrypted = []
        for entry_id, site, site_user, enc_pw, created_at in entries:
            plaintext = Fernet(old_key).decrypt(enc_pw.encode()).decode()
            new_enc   = Fernet(new_key).encrypt(plaintext.encode()).decode()
            reencrypted.append((new_enc, entry_id))
        # All decryptions succeeded — write in one transaction
        with cls._connect() as conn:
            for new_enc, entry_id in reencrypted:
                conn.execute(
                    "UPDATE vault SET encrypted_password=? WHERE id=?",
                    (new_enc, entry_id))

    @classmethod
    def insert_vault_entry(cls, username, site, site_username, encrypted_password):
        with cls._connect() as conn:
            conn.execute(
                "INSERT INTO vault "
                "(username, site, site_username, encrypted_password, created_at) "
                "VALUES (?,?,?,?,?)",
                (username, site, site_username, encrypted_password, time.time()))

    @classmethod
    def get_vault_entries(cls, username):
        with cls._connect() as conn:
            return conn.execute(
                "SELECT id, site, site_username, encrypted_password, created_at "
                "FROM vault WHERE username=? ORDER BY created_at DESC",
                (username,)).fetchall()

    @classmethod
    def delete_vault_entry(cls, entry_id):
        with cls._connect() as conn:
            conn.execute("DELETE FROM vault WHERE id=?", (entry_id,))


# ══════════════════════════════════════════════════════════════════════════════
#  GRID COLOR PALETTE
# ══════════════════════════════════════════════════════════════════════════════

GRID_PALETTE = [
    "#E53E3E", "#3B82F6", "#22C55E", "#EAB308",
    "#F97316", "#A855F7", "#EC4899", "#14B8A6", "#F59E0B",
]

GRID_COLOR_NAMES = {
    "#E53E3E": "Red",    "#3B82F6": "Blue",   "#22C55E": "Green",
    "#EAB308": "Yellow", "#F97316": "Orange", "#A855F7": "Purple",
    "#EC4899": "Pink",   "#14B8A6": "Teal",   "#F59E0B": "Amber",
}


def is_adjacent(a, b):
    ar, ac = divmod(a, 3)
    br, bc = divmod(b, 3)
    return abs(ar - br) <= 1 and abs(ac - bc) <= 1 and a != b


# ══════════════════════════════════════════════════════════════════════════════
#  PATTERN GRID WIDGET  — plain tk.Canvas
# ══════════════════════════════════════════════════════════════════════════════

class PatternGrid:
    CELL    = 72
    PAD     = 12
    RADIUS  = 28
    DOT_R   = 8
    LABEL_H = 18

    def __init__(self, parent, colors, on_change=None):
        self.colors    = colors
        self.on_change = on_change
        self.sequence  = []
        self._dragging = False

        grid_w = 3 * self.CELL + 4 * self.PAD
        grid_h = 3 * (self.CELL + self.LABEL_H) + 4 * self.PAD

        self.canvas = tk.Canvas(parent, width=grid_w, height=grid_h,
                                bg=Theme.P_BG, highlightthickness=0)
        self.canvas.pack(pady=8)
        self._draw_grid()

        self.canvas.bind("<ButtonPress-1>",   self._on_press)
        self.canvas.bind("<B1-Motion>",       self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)

    def _cell_center(self, idx):
        row, col = divmod(idx, 3)
        cx = self.PAD + col * (self.CELL + self.PAD) + self.CELL // 2
        cy = self.PAD + row * (self.CELL + self.LABEL_H + self.PAD) + self.CELL // 2
        return cx, cy

    def _label_pos(self, idx):
        cx, cy = self._cell_center(idx)
        return cx, cy + self.RADIUS + 2 + self.LABEL_H // 2

    def _cell_at(self, x, y):
        for i in range(9):
            cx, cy = self._cell_center(i)
            if (x - cx) ** 2 + (y - cy) ** 2 <= self.RADIUS ** 2:
                return i
        return None

    def _draw_grid(self):
        self.canvas.delete("all")
        for k in range(len(self.sequence) - 1):
            ax, ay = self._cell_center(self.sequence[k])
            bx, by = self._cell_center(self.sequence[k + 1])
            self.canvas.create_line(ax, ay, bx, by,
                                    fill=Theme.P_ACCENT, width=3, smooth=True)
        for i in range(9):
            cx, cy = self._cell_center(i)
            lx, ly = self._label_pos(i)
            color  = self.colors[i]
            name   = GRID_COLOR_NAMES.get(color, "")
            sel    = i in self.sequence

            if sel:
                self.canvas.create_oval(
                    cx-self.RADIUS-6, cy-self.RADIUS-6,
                    cx+self.RADIUS+6, cy+self.RADIUS+6,
                    outline=color, width=2, fill="")

            fill = color if sel else self._dim(color)
            self.canvas.create_oval(
                cx-self.RADIUS, cy-self.RADIUS,
                cx+self.RADIUS, cy+self.RADIUS,
                fill=fill, outline="")

            if sel:
                self.canvas.create_text(
                    cx, cy, text=str(self.sequence.index(i)+1),
                    fill="white", font=("Helvetica", 13, "bold"))
            else:
                self.canvas.create_oval(
                    cx-self.DOT_R, cy-self.DOT_R,
                    cx+self.DOT_R, cy+self.DOT_R,
                    fill=self._dim(color, more=True), outline="")

            self.canvas.create_text(
                lx, ly, text=name,
                fill=color if sel else self._dim(color),
                font=("Helvetica", 8, "bold" if sel else "normal"))

    def _dim(self, hex_color, more=False):
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
        f = 0.25 if more else 0.45
        return f"#{int(r*f):02x}{int(g*f):02x}{int(b*f):02x}"

    def _try_add_drag(self, idx):
        if idx is None or idx in self.sequence: return
        if self.sequence and not is_adjacent(self.sequence[-1], idx): return
        self.sequence.append(idx)
        self._draw_grid()
        if self.on_change: self.on_change(self.sequence)

    def _try_add_tap(self, idx):
        if idx is None or idx in self.sequence: return
        self.sequence.append(idx)
        self._draw_grid()
        if self.on_change: self.on_change(self.sequence)

    def _on_press(self, event):
        self._dragging = False
        idx = self._cell_at(event.x, event.y)
        if idx is None: return
        if not self.sequence:
            self.sequence = [idx]
            self._draw_grid()
            if self.on_change: self.on_change(self.sequence)
        else:
            self._try_add_tap(idx)

    def _on_drag(self, event):
        self._dragging = True
        self._try_add_drag(self._cell_at(event.x, event.y))

    def _on_release(self, event):
        self._dragging = False

    def reset(self):
        self.sequence = []
        self._draw_grid()
        if self.on_change: self.on_change(self.sequence)

    def flash_error(self):
        original = self.colors[:]
        self.colors = ["#E53E3E"] * 9
        self._draw_grid()
        self.canvas.after(500, lambda: self._restore(original))

    def _restore(self, original):
        self.colors = original
        self.reset()


# ══════════════════════════════════════════════════════════════════════════════
#  PATTERN VIEW  — plain tk Toplevel (dark theme)
# ══════════════════════════════════════════════════════════════════════════════

class PatternView:
    MAX_ATTEMPTS = 3

    def __init__(self, app):
        self.app = app

    def show_setup_prompt(self, username):
        grid_colors = random.sample(GRID_PALETTE, 9)
        salt        = Crypto.generate_salt()
        self._open_creation(username, grid_colors, salt)

    def _open_creation(self, username, grid_colors, salt):
        win = tk.Toplevel(self.app.root)
        win.title("Create Pattern")
        win.configure(bg=Theme.P_BG)
        win.resizable(False, False)
        self._center(win, 400, 640)

        self._panel_header(win, "🎨  Draw Your Pattern",
                           "Connect at least 4 colored cells to create your key")

        body = tk.Frame(win, bg=Theme.P_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 0))

        status_var = tk.StringVar(value="Tap or drag to start drawing")
        tk.Label(body, textvariable=status_var, bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9, "italic")).pack(pady=(0, 4))

        def on_change(seq):
            n = len(seq)
            if n == 0:   status_var.set("Tap or drag to start drawing")
            elif n < 4:  status_var.set(f"{n} cell{'s' if n>1 else ''} selected — need at least 4")
            elif n < 9:  status_var.set(f"{n} cells — good! Keep going or save")
            else:        status_var.set("Maximum 9 cells — press Save")

        grid = PatternGrid(body, grid_colors, on_change=on_change)

        tk.Label(body, text="💡  Tap cells one by one or click and drag in one motion",
                 bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8)).pack(pady=(0, 6))

        tk.Frame(body, bg=Theme.P_BORDER, height=1).pack(fill=tk.X, pady=(4, 10))
        btn_row = tk.Frame(body, bg=Theme.P_BG)
        btn_row.pack(fill=tk.X, padx=4)

        tk.Button(btn_row, text="Reset", bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                  font=("Helvetica", 10), relief="flat", bd=0, padx=16, pady=8,
                  cursor="hand2", activebackground=Theme.P_BORDER,
                  command=grid.reset).pack(side=tk.LEFT)

        tk.Button(btn_row, text="Save Pattern  →", bg=Theme.P_ACCENT, fg="white",
                  font=("Helvetica", 10, "bold"), relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  activebackground=Theme.ACCENT_DARK,
                  command=lambda: self._confirm_creation(
                      username, grid, grid_colors, salt, win)).pack(side=tk.RIGHT)

        self._panel_footer(win)

    def _confirm_creation(self, username, grid, grid_colors, salt, win):
        if len(grid.sequence) < 4:
            messagebox.showwarning("Too Short",
                "Please connect at least 4 cells to create a secure pattern.")
            return
        # Generate recovery code — show BEFORE saving so user must acknowledge
        recovery_code = Crypto.generate_recovery_code()
        self._show_recovery_code_modal(
            recovery_code,
            on_confirmed=lambda: self._save_pattern_and_proceed(
                username, grid, grid_colors, salt, recovery_code, win))

    def _save_pattern_and_proceed(self, username, grid, grid_colors, salt,
                                  recovery_code, win):
        code_hash = Crypto.hash_recovery_code(recovery_code)
        Database.insert_pattern(username, grid_colors, grid.sequence,
                                salt, code_hash)
        win.destroy()
        self._toast("Pattern saved!",
                    "You can now log in with your username and this pattern.")
        self.app.login_view.show()

    def _show_recovery_code_modal(self, code, on_confirmed):
        """
        Blocking modal — user must tick the checkbox before they can continue.
        """
        modal = tk.Toplevel(self.app.root)
        modal.title("Save Your Recovery Code")
        modal.configure(bg=Theme.P_BG)
        modal.resizable(False, False)
        self._center(modal, 460, 400)
        modal.grab_set()

        # Header strip
        hdr = tk.Frame(modal, bg=Theme.P_ACCENT, height=4)
        hdr.pack(fill=tk.X)

        body = tk.Frame(modal, bg=Theme.P_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=28, pady=20)

        tk.Label(body, text="🔑  Your Recovery Code",
                 bg=Theme.P_BG, fg=Theme.P_TEXT,
                 font=("Georgia", 14, "bold")).pack(pady=(0, 6))

        tk.Label(body,
                 text="If you ever forget your pattern, this code is the\n"
                      "ONLY way to regain access. It will never be shown again.",
                 bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9), justify="center").pack(pady=(0, 16))

        # Code display box
        code_frame = tk.Frame(body, bg=Theme.P_CARD,
                              highlightbackground=Theme.P_ACCENT,
                              highlightthickness=2)
        code_frame.pack(fill=tk.X, pady=(0, 8))

        code_lbl = tk.Label(code_frame, text=code,
                            bg=Theme.P_CARD, fg=Theme.P_ACCENT,
                            font=("Courier", 18, "bold"),
                            pady=14)
        code_lbl.pack()

        # Copy button
        def copy_code():
            modal.clipboard_clear()
            modal.clipboard_append(code)
            copy_btn.configure(text="✓  Copied!", fg=Theme.P_ACCENT)
            modal.after(2000, lambda: copy_btn.configure(
                text="Copy to clipboard", fg=Theme.P_SUBTEXT))

        copy_btn = tk.Button(body, text="Copy to clipboard",
                             bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                             font=("Helvetica", 9), relief="flat", bd=0,
                             cursor="hand2", pady=4,
                             activebackground=Theme.P_BORDER,
                             command=copy_code)
        copy_btn.pack(pady=(0, 14))

        # Checkbox acknowledgement
        confirmed = tk.BooleanVar(value=False)
        chk_frame = tk.Frame(body, bg=Theme.P_BG)
        chk_frame.pack(fill=tk.X, pady=(0, 16))

        chk = tk.Checkbutton(
            chk_frame,
            text="  I have saved my recovery code in a safe place",
            variable=confirmed,
            bg=Theme.P_BG, fg=Theme.P_TEXT,
            selectcolor=Theme.P_CARD,
            activebackground=Theme.P_BG,
            font=("Helvetica", 9),
            cursor="hand2",
            command=lambda: continue_btn.configure(
                bg=Theme.P_ACCENT if confirmed.get() else Theme.P_CARD,
                fg="white"        if confirmed.get() else Theme.P_SUBTEXT,
                cursor="hand2"    if confirmed.get() else "arrow",
            )
        )
        chk.pack(anchor="w")

        # Continue button — disabled until checkbox ticked
        def on_continue():
            if not confirmed.get():
                return
            modal.destroy()
            on_confirmed()

        continue_btn = tk.Button(body, text="I understand — continue  →",
                                 bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                                 font=("Helvetica", 10, "bold"),
                                 relief="flat", bd=0, pady=10,
                                 cursor="arrow",
                                 activebackground=Theme.ACCENT_DARK,
                                 activeforeground="white",
                                 command=on_continue)
        continue_btn.pack(fill=tk.X)

    def show_verification_window(self, username):
        result = Database.get_pattern(username)
        if not result:
            messagebox.showerror("Error", "No pattern found for this account.")
            self.app.login_view.show()
            return

        grid_colors, stored_seq, salt, _ = result

        win = tk.Toplevel(self.app.root)
        win.title("Verify Pattern")
        win.configure(bg=Theme.P_BG)
        win.resizable(False, False)
        self._center(win, 400, 640)

        remaining = self.MAX_ATTEMPTS - Database.get_failed_attempts(username)
        self._panel_header(win, "🔑  Enter Your Pattern",
                           f"Draw your saved pattern  ·  {remaining} attempt(s) left")

        body = tk.Frame(win, bg=Theme.P_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 0))

        status_var = tk.StringVar(value="Recreate your pattern to continue")
        tk.Label(body, textvariable=status_var, bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9, "italic")).pack(pady=(0, 4))

        def on_change(seq):
            n = len(seq)
            status_var.set("Recreate your pattern to continue" if n == 0
                           else f"{n} cell{'s' if n>1 else ''} entered...")

        grid = PatternGrid(body, grid_colors, on_change=on_change)

        tk.Label(body, text="💡  Tap cells one by one or click and drag in one motion",
                 bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8)).pack(pady=(0, 6))

        tk.Frame(body, bg=Theme.P_BORDER, height=1).pack(fill=tk.X, pady=(4, 10))
        btn_row = tk.Frame(body, bg=Theme.P_BG)
        btn_row.pack(fill=tk.X, padx=4)

        tk.Button(btn_row, text="Reset", bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                  font=("Helvetica", 10), relief="flat", bd=0, padx=16, pady=8,
                  cursor="hand2", activebackground=Theme.P_BORDER,
                  command=grid.reset).pack(side=tk.LEFT)

        tk.Button(btn_row, text="Confirm  →", bg=Theme.P_ACCENT, fg="white",
                  font=("Helvetica", 10, "bold"), relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  activebackground=Theme.ACCENT_DARK,
                  command=lambda: self._validate(
                      username, grid, stored_seq, salt, win)).pack(side=tk.RIGHT)

        self._panel_footer(win)

    def _validate(self, username, grid, stored_seq, salt, win):
        if len(grid.sequence) < 4:
            messagebox.showwarning("Too Short", "Please draw your full pattern.")
            return

        if grid.sequence == stored_seq:
            Database.reset_failed_attempts(username)
            key = Crypto.derive_key(grid.sequence, salt)
            self.app.session.open(username, key)
            win.destroy()
            self.app.home_view.show()
        else:
            Database.increment_failed_attempts(username)
            attempts  = Database.get_failed_attempts(username)
            remaining = self.MAX_ATTEMPTS - attempts
            if remaining <= 0:
                Database.lock_user(username)
                grid.flash_error()
                win.after(600, lambda: [
                    win.destroy(),
                    messagebox.showerror("Account Locked",
                        "3 incorrect attempts. Account locked for 24 hours.")])
            else:
                grid.flash_error()
                messagebox.showwarning("Wrong Pattern",
                    f"Wrong pattern — {remaining} attempt(s) left")

    def _toast(self, title, message):
        t = tk.Toplevel(self.app.root)
        t.configure(bg=Theme.P_BG)
        t.resizable(False, False)
        self._center(t, 340, 170)
        t.overrideredirect(True)
        outer = tk.Frame(t, bg=Theme.P_ACCENT)
        outer.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        inner = tk.Frame(outer, bg=Theme.P_CARD)
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        tk.Label(inner, text="✓", bg=Theme.P_CARD, fg=Theme.P_ACCENT,
                 font=("Georgia", 22, "bold")).pack(pady=(16, 2))
        tk.Label(inner, text=title, bg=Theme.P_CARD, fg=Theme.P_TEXT,
                 font=("Georgia", 12, "bold")).pack()
        tk.Label(inner, text=message, bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8), wraplength=280).pack(pady=(2, 8))
        tk.Button(inner, text="Continue", bg=Theme.P_ACCENT, fg="white",
                  font=("Helvetica", 9, "bold"), relief="flat", bd=0,
                  padx=20, pady=6, cursor="hand2",
                  command=t.destroy).pack(pady=(0, 14))

    @staticmethod
    def _panel_header(win, title, subtitle):
        hf = tk.Frame(win, bg=Theme.P_CARD)
        hf.pack(fill=tk.X)
        tk.Frame(hf, bg=Theme.P_ACCENT, height=3).pack(fill=tk.X)
        tk.Label(hf, text=title, bg=Theme.P_CARD, fg=Theme.P_TEXT,
                 font=("Georgia", 15, "bold")).pack(pady=(14, 2))
        tk.Label(hf, text=subtitle, bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9)).pack(pady=(0, 12))
        tk.Frame(hf, bg=Theme.P_BORDER, height=1).pack(fill=tk.X)

    @staticmethod
    def _panel_footer(win):
        tk.Frame(win, bg=Theme.P_BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(win, text="© 2025  Secure Vault", bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8)).pack(side=tk.BOTTOM, pady=5)

    @staticmethod
    def _center(win, w, h):
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sx-w)//2}+{(sy-h)//2}")


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNUP VIEW
# ══════════════════════════════════════════════════════════════════════════════

class SignupView:
    def __init__(self, app):
        self.app          = app
        self._debounce_id = None
        self._username_ok = False
        self.win          = self._build()

    def show(self):
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self._set_avail("", "neutral")
        self._username_ok = False
        self.win.deiconify()
        self.win.lift()
        self.win.after(50, self.username_entry.focus)

    def hide(self):
        self.win.withdraw()

    def _build(self):
        win = ctk.CTkToplevel(self.app.root)
        win.title("Create Account")
        win.resizable(False, False)
        self._center(win, 420, 520)
        win.withdraw()

        hdr = ctk.CTkFrame(win, fg_color=Theme.ACCENT, corner_radius=0, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="Create Account",
                     font=ctk.CTkFont("Georgia", 20, "bold"),
                     text_color="white").pack(expand=True)

        inner = ctk.CTkFrame(win, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=36, pady=20)

        ctk.CTkLabel(inner, text="Username",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")

        self.username_entry = ctk.CTkEntry(inner, height=40,
                                           placeholder_text="Choose a username")
        self.username_entry.pack(fill="x", pady=(4, 2))

        self.avail_label = ctk.CTkLabel(inner, text="", anchor="w",
                                        font=ctk.CTkFont(size=11))
        self.avail_label.pack(fill="x", pady=(0, 10))

        self._win_ref = win
        self.username_entry.bind("<KeyRelease>", self._on_key)

        ctk.CTkLabel(inner, text="Password",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")

        pw_row = ctk.CTkFrame(inner, fg_color="transparent")
        pw_row.pack(fill="x", pady=(4, 4))

        self.password_entry = ctk.CTkEntry(pw_row, height=40,
                                           placeholder_text="Create a password",
                                           show="•")
        self.password_entry.pack(side="left", fill="x", expand=True)

        self._pw_visible = False
        self.toggle_btn  = ctk.CTkButton(pw_row, text="Show", width=60, height=40,
                                         fg_color=Theme.BORDER,
                                         hover_color=Theme.ACCENT_DARK,
                                         command=self._toggle_pw)
        self.toggle_btn.pack(side="left", padx=(6, 0))

        ctk.CTkLabel(inner,
                     text="You won't need this again — your color pattern replaces it.",
                     font=ctk.CTkFont(size=10), text_color=Theme.TEXT_MID,
                     wraplength=320, anchor="w", justify="left").pack(fill="x", pady=(4, 18))

        ctk.CTkButton(inner, text="Continue to Pattern Setup →", height=44,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._on_signup).pack(fill="x")

        return win

    def _on_key(self, event=None):
        if self._debounce_id:
            self._win_ref.after_cancel(self._debounce_id)
        username = self.username_entry.get().strip()
        if not username:
            self._set_avail("", "neutral")
            self._username_ok = False
            return
        self._debounce_id = self._win_ref.after(
            500, lambda: self._check(username))

    def _check(self, username):
        self._debounce_id = None
        if self.username_entry.get().strip() != username:
            return
        if Database.user_exists(username):
            self._set_avail("✗  Username already taken", "taken")
            self._username_ok = False
        else:
            self._set_avail("✓  Username available", "available")
            self._username_ok = True

    def _set_avail(self, text, state):
        colors = {"available": Theme.ACCENT_LIGHT,
                  "taken":     Theme.V_RED,
                  "neutral":   Theme.TEXT_MID}
        self.avail_label.configure(text=text,
                                   text_color=colors.get(state, Theme.TEXT_MID))

    def _toggle_pw(self):
        self._pw_visible = not self._pw_visible
        self.password_entry.configure(show="" if self._pw_visible else "•")
        self.toggle_btn.configure(text="Hide" if self._pw_visible else "Show")

    def _on_signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Sign Up Failed",
                                 "Both username and password are required.")
            return
        if Database.user_exists(username):
            self._set_avail("✗  Username already taken", "taken")
            return
        Database.insert_user(username, password)
        self.hide()
        self.app.pattern_view.show_setup_prompt(username)

    @staticmethod
    def _center(win, w, h):
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sx-w)//2}+{(sy-h)//2}")


# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN VIEW
# ══════════════════════════════════════════════════════════════════════════════

class LoginView:
    def __init__(self, app):
        self.app = app
        self._build()

    def show(self):
        self.username_entry.delete(0, tk.END)
        self.app.root.deiconify()
        self.app.root.lift()
        self.username_entry.focus()

    def _build(self):
        root = self.app.root
        self._center(root, 420, 480)

        hdr = ctk.CTkFrame(root, fg_color=Theme.ACCENT, corner_radius=0, height=72)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔐  Secure Vault",
                     font=ctk.CTkFont("Georgia", 22, "bold"),
                     text_color="white").pack(expand=True)

        card = ctk.CTkFrame(root, corner_radius=12)
        card.pack(fill="both", expand=True, padx=36, pady=28)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=28, pady=28)

        ctk.CTkLabel(inner, text="Enter your username to continue",
                     text_color=Theme.TEXT_MID,
                     font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(0, 18))

        ctk.CTkLabel(inner, text="Username",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")

        self.username_entry = ctk.CTkEntry(inner, height=42,
                                           placeholder_text="Your username")
        self.username_entry.pack(fill="x", pady=(4, 18))
        self.username_entry.bind("<Return>", lambda e: self._on_login())

        ctk.CTkButton(inner, text="Continue →", height=44,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._on_login).pack(fill="x")

        forgot_lbl = ctk.CTkLabel(inner, text="Forgot your pattern?",
                                  text_color=Theme.TEXT_MID,
                                  font=ctk.CTkFont(size=11),
                                  cursor="hand2")
        forgot_lbl.pack(pady=(8, 0))
        forgot_lbl.bind("<Button-1>", lambda e: self._go_recovery())

        ctk.CTkFrame(inner, height=1, fg_color=Theme.BORDER).pack(fill="x", pady=18)

        bottom = ctk.CTkFrame(inner, fg_color="transparent")
        bottom.pack()
        ctk.CTkLabel(bottom, text="Don't have an account?",
                     text_color=Theme.TEXT_MID,
                     font=ctk.CTkFont(size=11)).pack(side="left")
        sl = ctk.CTkLabel(bottom, text=" Sign Up",
                          text_color=Theme.ACCENT,
                          font=ctk.CTkFont(size=11, weight="bold"),
                          cursor="hand2")
        sl.pack(side="left")
        sl.bind("<Button-1>", lambda e: self._go_signup())

        ctk.CTkLabel(root, text="© 2025  Secure Vault  ·  All rights reserved",
                     text_color=Theme.TEXT_MID,
                     font=ctk.CTkFont(size=9)).pack(pady=(0, 8))

    def _on_login(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Required", "Please enter your username.")
            return
        if not Database.user_exists(username):
            self._not_found_dialog()
            return
        locked_until = Database.get_locked_until(username)
        if locked_until and time.time() < locked_until:
            hrs = (locked_until - time.time()) / 3600
            messagebox.showerror("Account Locked",
                f"Account locked. Try again in {hrs:.1f} hour(s).")
            return
        self.app.root.withdraw()
        self.app.pattern_view.show_verification_window(username)

    def _not_found_dialog(self):
        d = ctk.CTkToplevel(self.app.root)
        d.title("Account Not Found")
        d.resizable(False, False)
        self._center(d, 340, 200)
        d.grab_set()
        ctk.CTkLabel(d, text="Account Not Found",
                     font=ctk.CTkFont("Georgia", 14, "bold")).pack(pady=(22, 6))
        ctk.CTkLabel(d,
                     text="No account found for that username.\nWould you like to sign up?",
                     text_color=Theme.TEXT_MID,
                     font=ctk.CTkFont(size=11), justify="center").pack(pady=(0, 20))
        row = ctk.CTkFrame(d, fg_color="transparent")
        row.pack()
        ctk.CTkButton(row, text="Try Again", width=110, height=36,
                      fg_color=Theme.BORDER, hover_color=Theme.ACCENT_DARK,
                      command=d.destroy).pack(side="left", padx=8)
        ctk.CTkButton(row, text="Sign Up →", width=110, height=36,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      command=lambda: [d.destroy(), self._go_signup()]).pack(
                          side="left", padx=8)

    def _go_recovery(self):
        self.app.recovery_view.show()

    def _go_signup(self):
        self.app.root.withdraw()
        self.app.signup_view.show()

    @staticmethod
    def _center(win, w, h):
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sx-w)//2}+{(sy-h)//2}")


# ══════════════════════════════════════════════════════════════════════════════
#  RECOVERY VIEW  — reset pattern via recovery code
# ══════════════════════════════════════════════════════════════════════════════

class RecoveryView:
    def __init__(self, app):
        self.app = app

    def show(self):
        win = ctk.CTkToplevel(self.app.root)
        win.title("Account Recovery")
        win.resizable(False, False)
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"420x400+{(sx-420)//2}+{(sy-400)//2}")
        win.grab_set()

        # Header
        hdr = ctk.CTkFrame(win, fg_color=Theme.ACCENT, corner_radius=0, height=58)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="🔑  Account Recovery",
                     font=ctk.CTkFont("Georgia", 17, "bold"),
                     text_color="white").pack(expand=True)

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=32, pady=22)

        ctk.CTkLabel(body,
                     text="Enter your username and 24-character recovery code\n"
                          "to set a new pattern. Your vault data will be preserved.",
                     text_color=Theme.TEXT_MID,
                     font=ctk.CTkFont(size=11),
                     justify="center").pack(pady=(0, 18))

        # Username
        ctk.CTkLabel(body, text="Username",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")
        username_entry = ctk.CTkEntry(body, height=38,
                                      placeholder_text="Your username")
        username_entry.pack(fill="x", pady=(4, 14))

        # Recovery code
        ctk.CTkLabel(body, text="Recovery Code",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")
        code_entry = ctk.CTkEntry(body, height=38,
                                  placeholder_text="XXXXXX-XXXXXX-XXXXXX-XXXXXX",
                                  font=ctk.CTkFont(size=12, family="Courier"))
        code_entry.pack(fill="x", pady=(4, 6))

        status_lbl = ctk.CTkLabel(body, text="", anchor="w",
                                  font=ctk.CTkFont(size=11))
        status_lbl.pack(fill="x", pady=(0, 14))

        ctk.CTkFrame(body, height=1, fg_color=Theme.BORDER).pack(fill="x", pady=(0, 12))

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x")
        ctk.CTkButton(btn_row, text="Cancel", width=100, height=40,
                      fg_color=Theme.BORDER, hover_color=Theme.ACCENT_DARK,
                      command=win.destroy).pack(side="left")
        ctk.CTkButton(btn_row, text="Verify & Reset Pattern  →", height=40,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=lambda: self._verify(
                          username_entry, code_entry, status_lbl, win)
                      ).pack(side="right")

    def _verify(self, username_entry, code_entry, status_lbl, win):
        username = username_entry.get().strip()
        code     = code_entry.get().strip()

        if not username or not code:
            status_lbl.configure(text="Both fields are required.",
                                 text_color=Theme.V_RED)
            return

        if not Database.user_exists(username):
            status_lbl.configure(text="No account found for that username.",
                                 text_color=Theme.V_RED)
            return

        result = Database.get_pattern(username)
        if not result:
            status_lbl.configure(text="No pattern data found for this account.",
                                 text_color=Theme.V_RED)
            return

        _, old_seq, old_salt, stored_hash = result

        if not Crypto.verify_recovery_code(code, stored_hash):
            status_lbl.configure(text="✗  Invalid recovery code. Check and try again.",
                                 text_color=Theme.V_RED)
            return

        # Code verified — open new pattern setup
        win.destroy()
        old_key = Crypto.derive_key(old_seq, old_salt)
        self._open_new_pattern(username, old_key, stored_hash)

    def _open_new_pattern(self, username, old_key, old_code_hash):
        """Show a draw-new-pattern window. On save: re-encrypt vault + update DB."""
        new_colors = random.sample(GRID_PALETTE, 9)
        new_salt   = Crypto.generate_salt()

        pwin = tk.Toplevel(self.app.root)
        pwin.title("Set New Pattern")
        pwin.configure(bg=Theme.P_BG)
        pwin.resizable(False, False)
        sx, sy = pwin.winfo_screenwidth(), pwin.winfo_screenheight()
        pwin.geometry(f"400x660+{(sx-400)//2}+{(sy-660)//2}")

        # Header
        hf = tk.Frame(pwin, bg=Theme.P_CARD)
        hf.pack(fill=tk.X)
        tk.Frame(hf, bg=Theme.P_ACCENT, height=3).pack(fill=tk.X)
        tk.Label(hf, text="🎨  Set New Pattern",
                 bg=Theme.P_CARD, fg=Theme.P_TEXT,
                 font=("Georgia", 15, "bold")).pack(pady=(14, 2))
        tk.Label(hf, text="Draw at least 4 cells to replace your old pattern",
                 bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9)).pack(pady=(0, 12))
        tk.Frame(hf, bg=Theme.P_BORDER, height=1).pack(fill=tk.X)

        body = tk.Frame(pwin, bg=Theme.P_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(8, 0))

        status_var = tk.StringVar(value="Tap or drag to start drawing")
        tk.Label(body, textvariable=status_var, bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 9, "italic")).pack(pady=(0, 4))

        def on_change(seq):
            n = len(seq)
            if n == 0:   status_var.set("Tap or drag to start drawing")
            elif n < 4:  status_var.set(f"{n} cell{'s' if n>1 else ''} — need at least 4")
            elif n < 9:  status_var.set(f"{n} cells — good! Keep going or save")
            else:        status_var.set("Maximum 9 cells — press Save")

        grid = PatternGrid(body, new_colors, on_change=on_change)

        tk.Label(body, text="💡  Tap cells one by one or click and drag in one motion",
                 bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8)).pack(pady=(0, 6))

        tk.Frame(body, bg=Theme.P_BORDER, height=1).pack(fill=tk.X, pady=(4, 10))
        btn_row = tk.Frame(body, bg=Theme.P_BG)
        btn_row.pack(fill=tk.X, padx=4)

        tk.Button(btn_row, text="Reset", bg=Theme.P_CARD, fg=Theme.P_SUBTEXT,
                  font=("Helvetica", 10), relief="flat", bd=0, padx=16, pady=8,
                  cursor="hand2", activebackground=Theme.P_BORDER,
                  command=grid.reset).pack(side=tk.LEFT)

        tk.Button(btn_row, text="Save New Pattern  →",
                  bg=Theme.P_ACCENT, fg="white",
                  font=("Helvetica", 10, "bold"), relief="flat", bd=0,
                  padx=20, pady=8, cursor="hand2",
                  activebackground=Theme.ACCENT_DARK,
                  command=lambda: self._finalise_reset(
                      username, old_key, old_code_hash,
                      grid, new_colors, new_salt, pwin)
                  ).pack(side=tk.RIGHT)

        # Footer
        tk.Frame(pwin, bg=Theme.P_BORDER, height=1).pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(pwin, text="© 2025  Secure Vault", bg=Theme.P_BG, fg=Theme.P_SUBTEXT,
                 font=("Helvetica", 8)).pack(side=tk.BOTTOM, pady=5)

    def _finalise_reset(self, username, old_key, old_code_hash, grid,
                        new_colors, new_salt, pwin):
        if len(grid.sequence) < 4:
            messagebox.showwarning("Too Short",
                "Please connect at least 4 cells.")
            return

        new_key = Crypto.derive_key(grid.sequence, new_salt)

        # Re-encrypt vault under new key
        try:
            Database.reencrypt_vault(username, old_key, new_key)
        except Exception as e:
            messagebox.showerror("Re-encryption Failed",
                f"Could not re-encrypt vault: {e}\nYour old pattern is still active.")
            return

        # Keep the original recovery code hash — user already proved they have it
        Database.update_pattern(username, new_colors, grid.sequence,
                                new_salt, old_code_hash)
        Database.reset_failed_attempts(username)
        pwin.destroy()
        messagebox.showinfo("Pattern Reset",
            "Your pattern has been reset and vault re-encrypted.\n"
            "Your original recovery code is still valid.\n"
            "Please log in with your new pattern.")
        self.app.login_view.show()


# ══════════════════════════════════════════════════════════════════════════════
#  ADD CREDENTIAL MODAL
# ══════════════════════════════════════════════════════════════════════════════

class AddCredentialModal:
    def __init__(self, parent_win, app, on_save):
        self.app     = app
        self.on_save = on_save
        self._build(parent_win)

    def _build(self, parent):
        win = ctk.CTkToplevel(parent)
        win.title("Add Credential")
        win.resizable(False, False)
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"440x520+{(sx-440)//2}+{(sy-520)//2}")
        win.grab_set()

        hdr = ctk.CTkFrame(win, fg_color=Theme.V_ACCENT, corner_radius=0, height=54)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="Add New Credential",
                     font=ctk.CTkFont("Georgia", 15, "bold"),
                     text_color="white").pack(expand=True)

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=32, pady=20)

        ctk.CTkLabel(body, text="Site / App Name",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")
        self.site_entry = ctk.CTkEntry(body, height=38,
                                       placeholder_text="e.g. gmail.com")
        self.site_entry.pack(fill="x", pady=(4, 14))

        ctk.CTkLabel(body, text="Username / Email",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")
        self.user_entry = ctk.CTkEntry(body, height=38,
                                       placeholder_text="e.g. you@email.com")
        self.user_entry.pack(fill="x", pady=(4, 14))

        ctk.CTkLabel(body, text="Password",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").pack(fill="x")

        pw_row = ctk.CTkFrame(body, fg_color="transparent")
        pw_row.pack(fill="x", pady=(4, 2))

        self.pw_entry = ctk.CTkEntry(pw_row, height=38,
                                     placeholder_text="Enter or generate",
                                     show="•")
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_entry.bind("<KeyRelease>", lambda e: self._update_strength())

        self._pw_vis = False
        ctk.CTkButton(pw_row, text="👁", width=38, height=38,
                      fg_color=Theme.V_CARD, hover_color=Theme.V_BORDER,
                      command=self._toggle_pw).pack(side="left", padx=(4, 0))

        ctk.CTkButton(pw_row, text="Generate", width=82, height=38,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=11, weight="bold"),
                      command=self._generate).pack(side="left", padx=(4, 0))

        # Strength bar
        self.strength_bar = ctk.CTkProgressBar(body, height=6)
        self.strength_bar.pack(fill="x", pady=(6, 0))
        self.strength_bar.set(0)

        self.strength_label = ctk.CTkLabel(body, text="",
                                           font=ctk.CTkFont(size=10),
                                           anchor="w")
        self.strength_label.pack(fill="x")

        ctk.CTkFrame(body, height=1, fg_color=Theme.V_BORDER).pack(fill="x", pady=14)

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x")
        ctk.CTkButton(btn_row, text="Cancel", width=100, height=40,
                      fg_color=Theme.V_CARD, hover_color=Theme.V_BORDER,
                      command=win.destroy).pack(side="left")
        ctk.CTkButton(btn_row, text="Save  →", height=40,
                      fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=lambda: self._save(win)).pack(side="right")

    def _toggle_pw(self):
        self._pw_vis = not self._pw_vis
        self.pw_entry.configure(show="" if self._pw_vis else "•")

    def _generate(self):
        pwd = Crypto.generate_password()
        self.pw_entry.configure(show="")
        self.pw_entry.delete(0, tk.END)
        self.pw_entry.insert(0, pwd)
        self._pw_vis = True
        self._update_strength()
        self.pw_entry.clipboard_clear()
        self.pw_entry.clipboard_append(pwd)

    def _update_strength(self):
        pwd   = self.pw_entry.get()
        score = Crypto.score_password(pwd)
        labels = ["", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        colors = ["gray", Theme.V_RED, Theme.V_YELLOW,
                  Theme.V_YELLOW, Theme.V_GREEN, Theme.V_GREEN]
        self.strength_bar.set(score / 5)
        self.strength_bar.configure(progress_color=colors[score])
        self.strength_label.configure(
            text=labels[score] if pwd else "",
            text_color=colors[score])

    def _save(self, win):
        site     = self.site_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pw_entry.get()
        if not site or not username or not password:
            messagebox.showwarning("Incomplete", "All three fields are required.")
            return
        encrypted = Crypto.encrypt(self.app.session.key, password)
        Database.insert_vault_entry(self.app.session.username,
                                    site, username, encrypted)
        win.destroy()
        self.on_save()


# ══════════════════════════════════════════════════════════════════════════════
#  HOME VIEW  — vault dashboard
# ══════════════════════════════════════════════════════════════════════════════

class HomeView:
    def __init__(self, app):
        self.app = app
        self.win = None

    def show(self):
        if self.win and self.win.winfo_exists():
            self.win.destroy()

        win = ctk.CTkToplevel(self.app.root)
        win.title("Secure Vault")
        win.resizable(True, True)
        win.minsize(700, 460)
        sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"900x600+{(sx-900)//2}+{(sy-600)//2}")
        self.win = win

        self._build_topbar(win)
        self._build_body(win)

    def _build_topbar(self, win):
        bar = ctk.CTkFrame(win, fg_color=Theme.V_SIDEBAR,
                           corner_radius=0, height=56)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="🔐  Secure Vault",
                     font=ctk.CTkFont("Georgia", 16, "bold"),
                     text_color=Theme.V_TEXT).pack(side="left", padx=20)

        ctk.CTkButton(bar, text="＋  Add Credential", width=155, height=34,
                      fg_color=Theme.V_ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      command=self._add_credential).pack(side="right", padx=16)

        ctk.CTkLabel(bar, text=f"👤  {self.app.session.username}",
                     text_color=Theme.V_SUBTEXT,
                     font=ctk.CTkFont(size=12)).pack(side="right", padx=8)

        ctk.CTkButton(bar, text="Logout", width=80, height=34,
                      fg_color=Theme.V_CARD, hover_color=Theme.V_BORDER,
                      font=ctk.CTkFont(size=11),
                      command=self._logout).pack(side="right", padx=(0, 4))

    def _build_body(self, win):
        self.body = ctk.CTkFrame(win, fg_color=Theme.V_BG, corner_radius=0)
        self.body.pack(fill="both", expand=True)
        self._render_entries()

    def _render_entries(self):
        for w in self.body.winfo_children():
            w.destroy()

        entries = Database.get_vault_entries(self.app.session.username)

        if not entries:
            self._render_empty()
            return

        # Search bar
        sf = ctk.CTkFrame(self.body, fg_color="transparent")
        sf.pack(fill="x", padx=24, pady=(16, 8))
        self.search_var = ctk.StringVar()
        se = ctk.CTkEntry(sf, height=36,
                          placeholder_text="🔍  Search by site or username...",
                          textvariable=self.search_var)
        se.pack(fill="x")
        self.search_var.trace_add("write",
            lambda *_: self._filter_entries(entries))

        # Column headers
        hdr = ctk.CTkFrame(self.body, fg_color=Theme.V_SIDEBAR, height=34)
        hdr.pack(fill="x", padx=24)
        hdr.pack_propagate(False)
        for text, wd in [("  Site / App", 210), ("Username / Email", 210),
                          ("Password", 170), ("Actions", 200)]:
            ctk.CTkLabel(hdr, text=text,
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=Theme.V_SUBTEXT,
                         width=wd, anchor="w").pack(side="left", padx=4)

        self.scroll_frame = ctk.CTkScrollableFrame(
            self.body, fg_color="transparent", corner_radius=0)
        self.scroll_frame.pack(fill="both", expand=True, padx=24, pady=(0, 12))

        for row in entries:
            self._render_row(row)

    def _filter_entries(self, all_entries):
        query = self.search_var.get().lower()
        for w in self.scroll_frame.winfo_children():
            w.destroy()
        for row in all_entries:
            if query in row[1].lower() or query in row[2].lower():
                self._render_row(row)

    def _render_empty(self):
        ctk.CTkLabel(self.body,
                     text="🔒\n\nNo credentials saved yet",
                     font=ctk.CTkFont("Georgia", 18),
                     text_color=Theme.V_SUBTEXT,
                     justify="center").pack(expand=True)
        ctk.CTkButton(self.body, text="＋  Add your first credential",
                      height=44, width=260,
                      fg_color=Theme.V_ACCENT, hover_color=Theme.ACCENT_DARK,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._add_credential).pack(pady=(0, 100))

    def _render_row(self, row):
        entry_id, site, site_user, enc_pw, _ = row
        pw_revealed = {"v": False}

        card = ctk.CTkFrame(self.scroll_frame, fg_color=Theme.V_CARD,
                            corner_radius=8, height=52)
        card.pack(fill="x", pady=4)
        card.pack_propagate(False)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=12, pady=8)

        ctk.CTkLabel(inner, text=site,
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=Theme.V_TEXT,
                     width=210, anchor="w").pack(side="left")

        ctk.CTkLabel(inner, text=site_user,
                     font=ctk.CTkFont(size=12),
                     text_color=Theme.V_SUBTEXT,
                     width=210, anchor="w").pack(side="left")

        pw_var = ctk.StringVar(value="••••••••••••")
        pw_lbl = ctk.CTkLabel(inner, textvariable=pw_var,
                              font=ctk.CTkFont(size=12, family="Courier"),
                              text_color=Theme.V_SUBTEXT,
                              width=170, anchor="w")
        pw_lbl.pack(side="left")

        btn_frame = ctk.CTkFrame(inner, fg_color="transparent")
        btn_frame.pack(side="left")

        reveal_btn = ctk.CTkButton(btn_frame, text="Reveal", width=64, height=28,
                                   fg_color=Theme.V_CARD, hover_color=Theme.V_BORDER,
                                   font=ctk.CTkFont(size=11),
                                   border_width=1, border_color=Theme.V_BORDER)
        reveal_btn.pack(side="left", padx=(0, 4))

        copy_btn = ctk.CTkButton(btn_frame, text="Copy", width=54, height=28,
                                 fg_color=Theme.V_CARD, hover_color=Theme.V_BORDER,
                                 font=ctk.CTkFont(size=11),
                                 border_width=1, border_color=Theme.V_BORDER)
        copy_btn.pack(side="left", padx=(0, 4))

        del_btn = ctk.CTkButton(btn_frame, text="🗑", width=32, height=28,
                                fg_color=Theme.V_CARD, hover_color=Theme.V_RED,
                                font=ctk.CTkFont(size=12))
        del_btn.pack(side="left")

        def toggle_reveal():
            if not pw_revealed["v"]:
                pt = Crypto.decrypt(self.app.session.key, enc_pw)
                pw_var.set(pt if pt else "[error]")
                pw_lbl.configure(text_color=Theme.V_TEXT)
                reveal_btn.configure(text="Hide")
            else:
                pw_var.set("••••••••••••")
                pw_lbl.configure(text_color=Theme.V_SUBTEXT)
                reveal_btn.configure(text="Reveal")
            pw_revealed["v"] = not pw_revealed["v"]

        def copy_pw():
            pt = Crypto.decrypt(self.app.session.key, enc_pw)
            if pt:
                self.win.clipboard_clear()
                self.win.clipboard_append(pt)
                copy_btn.configure(text="✓ Done")
                self.win.after(2000, lambda: copy_btn.configure(text="Copy"))

        def confirm_delete():
            if messagebox.askyesno("Delete",
                    f'Delete credentials for "{site}"?'):
                Database.delete_vault_entry(entry_id)
                self._render_entries()

        reveal_btn.configure(command=toggle_reveal)
        copy_btn.configure(command=copy_pw)
        del_btn.configure(command=confirm_delete)

    def _add_credential(self):
        AddCredentialModal(self.win, self.app, on_save=self._render_entries)

    def _logout(self):
        self.app.session.close()
        if self.win:
            self.win.destroy()
        self.app.login_view.show()


# ══════════════════════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════════════════════

class App:
    def __init__(self):
        Database.create_tables()

        self.root = ctk.CTk()
        self.root.title("Secure Vault")
        self.root.resizable(False, False)

        self.session       = SessionManager()
        self.home_view     = HomeView(self)
        self.pattern_view  = PatternView(self)
        self.recovery_view = RecoveryView(self)
        self.login_view    = LoginView(self)
        self.signup_view   = SignupView(self)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
