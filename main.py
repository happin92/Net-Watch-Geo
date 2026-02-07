from sniffer import run_sniffer
import customtkinter as ctk
import threading

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

sniffing = False

def get_status():
    return sniffing

def start_button_clicked():
    global sniffing
    sniffing = True
    thread = threading.Thread(target=run_sniffer, args=(logs, get_status))
    thread.start()

def stop_button_clicked():
    global sniffing
    if sniffing:
        sniffing = False
        logs("Остановлено")
    else:
        logs("Остановлено")

def logs(message):
    log_text.insert("end", message + "\n")
    log_text.see("end")

if __name__ == "__main__":
    root = ctk.CTk()
    root.title("sniffer")
    root.geometry("600x450")
    root.resizable(False, False)

    log_text = ctk.CTkTextbox(root, width=580, height=300)
    log_text.pack(pady=10, padx=10)

    start_btn = ctk.CTkButton(root, text="Запустить анализ", command=start_button_clicked)
    start_btn.pack(pady=5)

    stop_btn = ctk.CTkButton(root, text="Остановить", command=stop_button_clicked)
    stop_btn.pack(pady=5)

    signature = ctk.CTkLabel(root, text="by happiness", text_color="gray50", font=("Arial", 12, "italic"))
    signature.pack(side="bottom", anchor="se", padx=10, pady=5)

    root.mainloop()