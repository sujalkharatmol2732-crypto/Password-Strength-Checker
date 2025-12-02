import tkinter as tk
from tkinter import ttk, messagebox, Canvas
import random
import re
from operator import itemgetter
import time

class PasswordChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("🐉 Dragon Password Analyzer Pro")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
        self.root.configure(bg="#0a0a1a")
        self.root.lift()
        self.root.resizable(True, True)
        
        self.passwords_list = []
        self.last_analyze_time = 0
        
        # 🐉 2-FINGER TOUCHPAD SCROLL SUPPORT
        self.root.bind_all("<MouseWheel>", self.on_mousewheel)
        self.root.bind_all("<Shift-MouseWheel>", self.on_shift_mousewheel)
        self.root.bind_all('<F5>', self.on_f5_press)
        self.root.bind_all('<Escape>', self.on_escape_press)
        
        self.show_startup_animation()
    
    def on_mousewheel(self, event):
        if hasattr(self, 'main_canvas'):
            self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def on_shift_mousewheel(self, event):
        if hasattr(self, 'main_canvas'):
            self.main_canvas.xview_scroll(int(-1*(event.delta/120)), "units")
    
    def on_f5_press(self, event):
        if hasattr(self, 'search_entry'):
            self.search_entry.focus()
        return "break"
    
    def on_escape_press(self, event):
        self.root.quit()
        return "break"
    
    def show_startup_animation(self):
        self.root.withdraw()
        splash = tk.Toplevel(self.root)
        splash.geometry("1000x750")
        splash.configure(bg="#0a0a1a")
        splash.overrideredirect(True)
        splash.lift()
        splash.attributes('-topmost', True)
        
        logo_canvas = Canvas(splash, width=1000, height=750, bg="#0a0a1a", highlightthickness=0)
        logo_canvas.pack()
        
        def animate_dragon():
            logo_canvas.delete("all")
            colors = ["#ff4d4d", "#ff8c00", "#ffd700", "#32cd32", "#89b4fa", "#a6e3a1"]
            color = colors[int(time.time() * 3) % len(colors)]
            for i in range(8):
                angle = i * 45
                radius = 150 + i * 20
                logo_canvas.create_arc(500-radius//2, 375-radius//2, 500+radius//2, 375+radius//2,
                                     start=angle, extent=30, width=6, outline=color, style="arc")
            logo_canvas.create_text(500, 300, text="🐉 DRAGON", font=("Segoe UI", 64, "bold"), fill=color)
            logo_canvas.create_text(500, 380, text="PASSWORD ANALYZER", font=("Segoe UI", 28, "bold"), fill="#94e2d5")
            logo_canvas.create_text(500, 450, text="PRO", font=("Segoe UI", 48, "bold"), fill="#f9e2af")
            dots = "⏳ LOADING" + "." * ((int(time.time() * 4) % 4) + 1)
            logo_canvas.create_text(500, 520, text=dots, font=("Consolas", 24, "bold"), fill="#89b4fa")
            progress = min((time.time() % 3) / 3 * 100, 100)
            logo_canvas.create_rectangle(350, 580, 350 + progress * 5, 610, fill="#a6e3a1", outline="#89b4fa", width=3)
            logo_canvas.create_rectangle(350, 580, 850, 610, outline="#45475a", width=3)
            splash.after(50, animate_dragon)
        
        animate_dragon()
        splash.after(3000, lambda: self.start_main_app(splash))
    
    def start_main_app(self, splash):
        splash.destroy()
        self.root.deiconify()
        self.root.after(100, self.setup_ui)  # Delay to ensure ready
    
    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#0a0a1a")
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        self.main_canvas = tk.Canvas(main_frame, bg="#0a0a1a", highlightthickness=0)
        v_scrollbar = tk.Scrollbar(main_frame, orient="vertical", width=16, 
                                 bg="#1a1a3e", troughcolor="#0a0a1a", command=self.main_canvas.yview)
        self.main_canvas.configure(yscrollcommand=v_scrollbar.set)
        v_scrollbar.pack(side="right", fill="y")
        self.main_canvas.pack(side="left", fill="both", expand=True)
        
        self.content_frame = tk.Frame(self.main_canvas, bg="#0a0a1a")
        self.main_canvas.create_window((0, 0), window=self.content_frame, anchor="nw", tags="content")
        self.main_canvas.bind('<Configure>', self.on_canvas_configure)
        self.content_frame.bind('<Configure>', self.on_frame_configure)
        
        self.build_content()
        self.root.update_idletasks()
        self.animate_title_glow()
    
    def on_canvas_configure(self, event):
        self.main_canvas.itemconfig("content", width=event.width-20)
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
    
    def on_frame_configure(self, event):
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
    
    def animate_title_glow(self):
        def glow_cycle():
            if hasattr(self, 'title'):
                colors = ["#89b4fa", "#a5b4fc", "#94e2d5", "#f9e2af", "#a6e3a1"]
                self.title.config(fg=colors[int(time.time() * 2) % len(colors)])
                if hasattr(self, 'pro_label'):
                    self.pro_label.config(fg=colors[int(time.time() * 4) % 3])
            self.root.after(500, glow_cycle)
        glow_cycle()
    
    def build_content(self):
        # Title
        title_frame = tk.Frame(self.content_frame, bg="#0a0a1a")
        title_frame.pack(pady=20)
        self.title = tk.Label(title_frame, text="🐉 DRAGON PASSWORD ANALYZER", font=("Segoe UI", 28, "bold"), fg="#89b4fa", bg="#0a0a1a")
        self.title.pack()
        self.pro_label = tk.Label(title_frame, text="PRO", font=("Segoe UI", 40, "bold"), fg="#f9e2af", bg="#0a0a1a")
        self.pro_label.pack()
        tk.Label(title_frame, text="✨ TYPE FOR INSTANT STRENGTH ANALYSIS ✨", font=("Segoe UI", 14), fg="#94e2d5", bg="#0a0a1a").pack(pady=(10,0))
        
        # Analyzer
        analyzer_frame = tk.Frame(self.content_frame, bg="#1a1a3e", relief="flat")
        analyzer_frame.pack(pady=20, padx=20, fill="x")
        tk.Label(analyzer_frame, text="⚡ LIGHTNING FAST ANALYZER", font=("Segoe UI", 16, "bold"), fg="#ffffff", bg="#1a1a3e").pack(pady=(20,15))
        
        input_frame = tk.Frame(analyzer_frame, bg="#1a1a3e")
        input_frame.pack(pady=15)
        self.search_entry = tk.Entry(input_frame, font=("Consolas", 16), show="*", relief="flat", bd=0, highlightthickness=3,
                                   highlightcolor="#89b4fa", highlightbackground="#2a2a4e", bg="#1e1e3e", fg="#e0e0ff", 
                                   insertbackground="#89b4fa", insertwidth=3, justify="center")
        self.search_entry.pack(pady=20, padx=(25,15), fill="x", expand=True)
        self.search_entry.focus()
        self.search_entry.bind('<KeyRelease>', self.super_fast_analyze)  # ✅ FIXED BINDING
        
        # Live meter
        self.meter_frame = tk.Frame(input_frame, bg="#1e1e3e")
        self.meter_frame.place(in_=self.search_entry, relx=0.97, rely=0.5, anchor="e")
        self.meter_frame.pack_propagate(False)
        self.meter_canvas = Canvas(self.meter_frame, width=110, height=110, bg="#1e1e3e", relief="flat", highlightthickness=0, bd=0)
        self.meter_canvas.pack()
        
        # Show toggle only
        ctrl_frame = tk.Frame(analyzer_frame, bg="#1a1a3e")
        ctrl_frame.pack(pady=15)
        self.show_var = tk.BooleanVar()
        self.show_check = tk.Checkbutton(ctrl_frame, text="👁 Show Password", variable=self.show_var, command=self.toggle_search_show, 
                      bg="#1a1a3e", fg="#cdd6f4", selectcolor="#2a2a4e", font=("Segoe UI", 12), bd=0)
        self.show_check.pack(side="left", padx=25)
        
        # Results - ALWAYS VISIBLE
        self.results_frame = tk.Frame(analyzer_frame, bg="#1a1a3e")
        self.results_frame.pack(pady=20, fill="x")
        
        self.score_label = tk.Label(self.results_frame, text="Score: 0%", font=("Segoe UI", 32, "bold"), bg="#1a1a3e", fg="#cdd6f4")
        self.score_label.pack(pady=10)
        
        self.stars_canvas = Canvas(self.results_frame, width=400, height=50, bg="#1a1a3e")
        self.stars_canvas.pack(pady=5)
        
        self.breach_label = tk.Label(self.results_frame, text="⚡ Type to start...", font=("Segoe UI", 14, "bold"), bg="#1a1a3e", fg="#89b4fa")
        self.breach_label.pack(pady=5)
        
        self.feedback_label = tk.Label(analyzer_frame, text="⚡ START TYPING → See strength % + missing requirements instantly!", 
                                     font=("Segoe UI", 12), fg="#94e2d5", bg="#1a1a3e", wraplength=700)
        self.feedback_label.pack(pady=(20,30))
        
        # Generator
        gen_frame = tk.Frame(self.content_frame, bg="#0a0a1a")
        gen_frame.pack(pady=15)
        tk.Label(gen_frame, text="🎲 Length:", font=("Segoe UI", 14, "bold"), fg="#f9e2af", bg="#0a0a1a").pack(side="left", padx=(20,10))
        self.length_var = tk.StringVar(value="16")
        tk.Spinbox(gen_frame, from_=12, to=25, width=5, textvariable=self.length_var, font=("Segoe UI", 14, "bold"),
                   bg="#2a2a4e", fg="#ffffff", relief="flat", bd=0).pack(side="left", padx=10)
        self.gen_btn = tk.Button(gen_frame, text="🐉 GENERATE TOP 50", command=self.generate_50_passwords, 
                               bg="#f9e2af", fg="#000", font=("Segoe UI", 14, "bold"), relief="flat", padx=30, pady=12, bd=0, cursor="hand2")
        self.gen_btn.pack(side="left", padx=15)
        
        # Passwords list
        self.passwords_frame = tk.Frame(self.content_frame, bg="#1a1a3e", relief="flat")
        self.passwords_frame.pack(pady=20, padx=20, fill="both", expand=True)
        tk.Label(self.passwords_frame, text="🥇 TOP 50 DRAGON PASSWORDS", font=("Segoe UI", 18, "bold"), fg="#16a34a", bg="#1a1a3e").pack(pady=(20,15))
        
        pwd_scroll_frame = tk.Frame(self.passwords_frame, bg="#1a1a3e")
        pwd_scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        pwd_scrollbar = tk.Scrollbar(pwd_scroll_frame, orient="vertical", width=14)
        self.pwd_canvas = tk.Canvas(pwd_scroll_frame, bg="#1a1a3e", yscrollcommand=pwd_scrollbar.set, relief="flat")
        pwd_scrollbar.config(command=self.pwd_canvas.yview)
        pwd_scrollbar.pack(side="right", fill="y")
        self.pwd_canvas.pack(side="left", fill="both", expand=True)
        self.pwd_content = tk.Frame(self.pwd_canvas, bg="#1a1a3e")
        self.pwd_canvas.create_window((0,0), window=self.pwd_content, anchor="nw")
        self.pwd_content.bind("<Configure>", lambda e: self.pwd_canvas.configure(scrollregion=self.pwd_canvas.bbox("all")))
        
        self.copy_btn = tk.Button(self.passwords_frame, text="🐉 COPY #1 PASSWORD", command=self.copy_top_password, 
                                bg="#a6e3a1", fg="#000", font=("Segoe UI", 13, "bold"), relief="flat", padx=35, pady=12, bd=0, cursor="hand2")
        self.copy_btn.pack(pady=20)
    
    def super_fast_analyze(self, event=None):
        """⚡ LIGHTNING FAST - WORKS FROM 1st CHARACTER!"""
        current_time = time.time()
        if current_time - self.last_analyze_time < 0.03:  # 30ms throttle
            return
        self.last_analyze_time = current_time
        
        password = self.search_entry.get().strip()
        if not password:
            self.score_label.config(text="Score: 0%", fg="#cdd6f4")
            self.breach_label.config(text="⚡ Type to start...", fg="#89b4fa")
            self.feedback_label.config(text="⚡ START TYPING → See strength % + missing requirements instantly!", fg="#94e2d5")
            self.draw_stars(0)
            self.draw_overlay_meter(0)
            return
        
        score, feedback, percent = self.check_strength(password)
        color = self.get_strength_color(score)
        
        # ✅ SHOW PERCENTAGE + SCORE
        self.score_label.config(text=f"Score: {score}/10 ({percent}%)", fg=color)
        
        # ✅ DETAILED FEEDBACK - WHAT'S MISSING
        missing_text = "✅ PERFECT!" if score >= 8 else "❌ MISSING: " + " | ".join(feedback)
        self.feedback_label.config(text=missing_text, fg=color)
        
        # Update visuals
        self.draw_stars(score)
        self.draw_overlay_meter(score)
        self.breach_label.config(text="⚡ LIVE SCAN - INSTANT", fg="#89b4fa")
    
    def draw_stars(self, score):
        self.stars_canvas.delete("all")
        for i in range(10):
            x = 20 + i * 36
            if i < score:
                self.stars_canvas.create_text(x, 25, text="⭐", font=("Arial", 22, "bold"), fill=self.get_strength_color(score))
            else:
                self.stars_canvas.create_text(x, 25, text="☆", font=("Arial", 22, "bold"), fill="#45475a")
    
    def draw_overlay_meter(self, score):
        self.meter_canvas.delete("all")
        cx, cy = 55, 55
        progress = (score/10)*360
        color = self.get_strength_color(score)
        self.meter_canvas.create_arc(cx-50, cy-50, cx+50, cy+50, start=270, extent=-progress, width=14,
                                   outline=color, style="arc", capstyle="round")
        percent = int(score/10*100)
        self.meter_canvas.create_text(cx, cy-5, text=f"{percent}%", font=("Consolas", 24, "bold"), fill=color)
    
    def toggle_search_show(self):
        self.search_entry.config(show="" if self.show_var.get() else "*")
    
    def get_strength_color(self, score):
        colors = ["#ff4d4d", "#ff6b35", "#ff8c00", "#ffaa00", "#ffd700", "#ffed4e", "#90ee90", "#32cd32", "#228b22", "#006400"]
        return colors[min(int(score), 9)]
    
    def check_strength(self, password):
        """⚡ RETURNS SCORE, FEEDBACK, PERCENTAGE"""
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*?_+\-=\[\]{}|":;,.~`]', password))  # More symbols
        no_repeat = len(set(password)) >= length * 0.8
        no_sequence = not re.search(r'(123|abc|qwe|asd|zxc|qwerty)', password.lower())
        
        score = 0
        feedback = []
        max_score = 10
        
        # Length (3 points)
        if length >= 20: score += 3
        elif length >= 16: score += 2
        elif length >= 12: score += 1
        else: feedback.append(f"Length ≥12 ({length})")
        
        # Requirements
        if not has_upper: feedback.append("UPPERCASE")
        else: score += 1
        if not has_lower: feedback.append("lowercase") 
        else: score += 1
        if not has_digit: feedback.append("NUMBERS")
        else: score += 1
        if not has_special: feedback.append("SYMBOLS !@#")
        else: score += 1
        
        # Advanced
        if no_repeat: score += 1
        else: feedback.append("No repeats")
        if no_sequence: score += 1
        else: feedback.append("No sequences")
        if len(re.findall(r'[A-Z]', password)) >= 2: score += 1
        if len(re.findall(r'[a-z]', password)) >= 3: score += 1
        
        score = min(score, max_score)
        percent = int((score/max_score) * 100)
        
        return score, feedback[:5], percent  # Limit feedback
    
    def generate_50_passwords(self):
        self.gen_btn.config(text="⏳ Generating...", state="disabled")
        self.root.update()
        try: length = int(self.length_var.get())
        except: length = 16
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*?_+-=[]{}|;:,.<>?/`~"
        passwords_data = []
        for i in range(500):
            pwd = ''.join(random.choice(chars) for _ in range(length))
            score, _, _ = self.check_strength(pwd)
            passwords_data.append((pwd, score))
            if len(passwords_data) >= 50: break
        self.passwords_list = sorted(passwords_data, key=itemgetter(1), reverse=True)
        self.root.after(100, self.display_passwords)
    
    def display_passwords(self):
        for widget in self.pwd_content.winfo_children():
            widget.destroy()
        if self.passwords_list:
            top_pwd, top_score = self.passwords_list[0]
            top_frame = tk.Frame(self.pwd_content, bg="#f59e0b")
            top_frame.pack(fill="x", padx=15, pady=12)
            tk.Label(top_frame, text="🐉 #1 KING", font=("Segoe UI", 13, "bold"), fg="white", bg="#f59e0b").pack(side="left", padx=12)
            tk.Label(top_frame, text=(top_pwd[:55]+"..." if len(top_pwd)>55 else top_pwd), font=("Consolas", 12), fg="white", bg="#f59e0b", wraplength=380).pack(side="left", padx=8, fill="x", expand=True)
            tk.Label(top_frame, text=f"{top_score}/10", font=("Segoe UI", 13, "bold"), fg="white", bg="#f59e0b").pack(side="right", padx=12)
            
            for i, (pwd, score) in enumerate(self.passwords_list[1:50]):
                rank = i + 2
                rank_bg = "#16a34a" if rank <= 3 else "#eab308" if rank <= 10 else "#2a2a4e"
                rank_text = "🥈🥉"[rank-2] if rank <= 3 else f"#{rank}"
                row = tk.Frame(self.pwd_content, bg=rank_bg, relief="solid", bd=1)
                row.pack(fill="x", padx=15, pady=5)
                tk.Label(row, text=rank_text, font=("Segoe UI", 11, "bold"), fg="white", bg=rank_bg, width=5).pack(side="left")
                tk.Label(row, text=(pwd[:50]+"..." if len(pwd)>50 else pwd), font=("Consolas", 11), fg="white", bg=rank_bg, wraplength=420).pack(side="left", padx=(12,8), fill="x", expand=True)
                tk.Label(row, text=f"{score}/10", font=("Segoe UI", 11, "bold"), fg="white", bg=rank_bg, width=5).pack(side="right", padx=8)
        self.gen_btn.config(text="🐉 NEW 50", state="normal")
        messagebox.showinfo("✅ COMPLETE!", "Top 50 Dragon passwords ready!")
    
    def copy_top_password(self):
        if self.passwords_list:
            top_pwd = self.passwords_list[0][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(top_pwd)
            messagebox.showinfo("🐉 COPIED!", f"🐉 #1 Dragon Password (Score: {self.passwords_list[0][1]}/10):\n\n{top_pwd}")
        else:
            messagebox.showwarning("⚠️", "Generate passwords first!")

if __name__ == "__main__":
    print("🐉 DRAGON ANALYZER v5.0  ⚡ FIXED LIGHTNING SCAN + % + MISSING INFO! - from flask import Flask, render_template.py:357")
    root = tk.Tk()
    app = PasswordChecker(root)
    root.mainloop()
