import tkinter
from tkinter import *
from tkinter import ttk
from PIL import Image, ImageTk
from tkinter import messagebox
import base64

# using interface  start Kullanici ara yuzu baslangic


my_font = "Times", "14", "bold italic"
back_color = "light blue"
window = Tk()
window.config(bg=back_color)
window.minsize(width=400, height=700)
window.title("Secret Notes")
# import an image
image_secret = Image.open('secretImage.jpg').resize((150, 100))
image_tk = ImageTk.PhotoImage(image_secret)


image_label = ttk.Label(window, text='security', image=image_tk)

image_label.pack()


title_label = Label()
title_label.config(text="Enter Your Title ", font=my_font, bg=back_color)
title_label.pack()


title_entry = Entry()
title_entry.config(width=20, font=1)

title_entry.pack()

secret_label = Label()
secret_label.config(text="Enter your secret", font=my_font, bg=back_color)
secret_label.pack()

myText = Text(width=30, height=20)
myText.config(pady=10, padx=10)
myText.pack()

masterkey_label = Label(text="Enter Master Key")
masterkey_label.config(font=my_font, bg=back_color)
masterkey_label.pack()
masterkey_entry = Entry()
masterkey_entry.config(font=1)
masterkey_entry.pack()


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

def saveFile():
    title= title_entry.get()
    message = myText.get(1.0,END)
    masterSecret = masterkey_entry.get()

    if len(title)== 0 or len(message) == 0 or len(masterSecret) == 0 :
        messagebox.showinfo(title = "Hata",message = "Bütün Alanlar Doldurulmalıdır.")
    else :
        # encrypt
        messageEncrypted = encode(masterSecret, message)



        try:
            with open("secret_text.txt","a") as dataFile :
                dataFile.write("\nBAŞLIK :" + title)
                dataFile.write("\nMESAJ : " + messageEncrypted)

                dataFile.write("\n---------------*****---------------")


        except FileNotFoundError :
            with open("secret_text.txt", "w") as dataFile :
                dataFile.write("\nBAŞLIK :" + title)
                dataFile.write("\nMESAJ : "+ messageEncrypted)

                dataFile.write("\n---------------*****---------------")
        finally:
            title_entry.delete(0, END)
            myText.delete('1.0', END)
            masterkey_entry.delete(0, END)

def decryptNotes ():
    try:
        messageEncrypted = myText.get("1.0",END)
        masterKey = masterkey_entry.get()
        if len(messageEncrypted)== 0 or len(masterKey)== 0 :
                 messagebox.showinfo(title = "Hata",message="Alanı Doldurmanız Gerek")
        else :
                decryptMesaage = decode(masterKey,messageEncrypted)
                myText.delete("1.0",END)
                myText.insert("1.0",decryptMesaage)
    except :
        messagebox.showinfo(title="Hata",message="Lütfen Şifrelenmiş Metin Girin")


        """
        file = open('secret_text.txt', 'a+')

        file.write("\nBAŞLIK :" + title )
        file.write("\nMESAJ : "+ message)
        file.write(("ANAHTARINIZ : "+masterSecret+'\n'))
        file.write("---------------*****---------------")
    title_entry.delete(0,END)
    myText.delete('1.0',END)
    masterkey_entry.delete(0,END)
    file.close() 
    """


save_button = Button(window)
save_button.config(text="Save & Encrypt", bg="light cyan",command =saveFile)
save_button.place(x=155, y=590)

decrypt_button = tkinter.Button()
decrypt_button.config(text="Decrypt", borderwidth=2, border=0.5, bg="light cyan",command=decryptNotes)

decrypt_button.place(x=175, y=620)

'''
sadik = Tk()

metinF = Text(sadik)
metinF.grid(row=9, column=1)

butonWrite = Button(sadik)
butonWrite.config(text = 'Write To File', command = writeFile)
butonWrite.grid(row=8, column=1)

sadik.mainloop()
'''






window.mainloop()
