from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64
#Window
window=Tk()
window.title("Top Secret")
window.minsize(400,800)
#MASTER KEY =secret
#Functions

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_encrypt():

    master_key=masterkey_entry.get()
    if master_key=="secret":
        title = title_entry.get()
        secret_text = secret_multiline.get("1.0", END)

        encrypted_text=encode(master_key,secret_text)
        try:
            with open("secret.txt", "a") as secret_file:
                secret_file.write(f"Title:{title}\n")
                secret_file.write(encrypted_text)
                secret_file.write("\n\n")
        except FileNotFoundError:
            with open("secret.txt","w") as secret_file:
                secret_file.write(f"Title:{title}\n")
                secret_file.write(encrypted_text)
                secret_file.write("\n\n")
        finally:
            title_entry.delete(0,END)
            secret_multiline.delete("1.0",END)
            masterkey_entry.delete(0,END)

    else:
        messagebox.showinfo(title="Error!",message="Please make sure of encrpyted info!")

def decrypt():
    password=secret_multiline.get("1.0",END)
    master_key=masterkey_entry.get()
    if master_key=="secret":
        try:
            decrypted_text=decode(master_key,password)
            secret_multiline.delete("1.0",END)
            secret_multiline.insert("1.0",decrypted_text)
        except:
            messagebox.showinfo(title="Error!",message="Please enter encrypted text")
    else:
        messagebox.showinfo(title="Error!", message="Please make sure of encrypted info!")


#Top-secret place
frame=Frame(window,width=10,height=10)
frame.pack()
#image-resource
img=ImageTk.PhotoImage(Image.open("secret.png"))
img_label=Label(frame,image=img)
img_label.pack()
#Title-Label
title_label=Label(text="Enter your title")
title_label.pack()
#Title-Entry
title_entry=Entry(width=30)
title_entry.pack()
#secret-label
secret_label=Label(text="Enter your secret")
secret_label.pack()
#secret-multiline
secret_multiline=Text(width=30,height=20)
secret_multiline.pack()
#master-key label
masterkey_label=Label(text="Enter master key")
masterkey_label.pack()
#master-key Entry
masterkey_entry=Entry(width=30)
masterkey_entry.pack()
#Save & Encrypt button
encrpty_button=Button(text="Save & Encrypt",command=save_encrypt)
encrpty_button.pack()
#Decrypt button
decrypt_button=Button(text="Decrypt",width=5,command=decrypt)
decrypt_button.pack()


window.mainloop()