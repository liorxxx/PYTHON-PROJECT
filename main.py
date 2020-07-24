import tkinter as tk
from tkinter.filedialog import askopenfilename
from design import *
from crypt import encrypt_message, decrypt_message
import datetime


root = tk.Tk()
root.title('Final Project')
root.geometry('1080x720')
root.resizable(False,False)
root.configure(bg=WINDOW_BACKGROUND)

#Frame Creations:
left_frame = tk.Frame(root, bg=WINDOW_BACKGROUND)
left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)

right_frame = tk.Frame(root, bg=WINDOW_BACKGROUND)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=tk.YES)

#Title Creations:
title_encryption = tk.Label(left_frame, text='Encryption', font=TITLE_DESIGN)
title_encryption.pack(side=tk.TOP)

title_entry_encrypt = tk.Label(left_frame, text = 'Text to Encrypt: ',font=SECONDARY_TITLE_DESIGN)
title_entry_encrypt.pack(side=tk.TOP)

title_decryption = tk.Label(right_frame, text='Decryption', font=TITLE_DESIGN)
title_decryption.pack(side=tk.TOP)

title_entry_decrypt = tk.Label(right_frame, text = 'Text to Decrypt: ',font=SECONDARY_TITLE_DESIGN)
title_entry_decrypt.pack(side=tk.TOP)

#Entry Creations
variable_encrypt = tk.StringVar(left_frame)
entry_encrypt = tk.Entry(left_frame, width=72,
                         textvariable=variable_encrypt)
entry_encrypt.pack(side=tk.TOP)

variable_decrypt = tk.StringVar(right_frame)
entry_decrypt = tk.Entry(right_frame, width=72,
                         textvariable=variable_decrypt)
entry_decrypt.pack(side=tk.TOP)

#Results:
result_text_encrypt = tk.Label(left_frame, text="", font=TEXT_DESIGN, bg=WINDOW_BACKGROUND)
result_text_encrypt.pack(side=tk.TOP, pady=100)

result_text_decrypt = tk.Label(right_frame, text="", font=TEXT_DESIGN, bg=WINDOW_BACKGROUND)
result_text_decrypt.pack(side=tk.TOP, pady=100)

#Functions of Buttons/File Saves:
def save_file(folder_name, text_to_write):
    file_name = str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
    file_to_write = open(f'{folder_name}\\{file_name}.txt', 'w')
    file_to_write.write(f'{text_to_write}')
    file_to_write.close()
    if 'encrypt' in folder_name.lower():
        result_text_encrypt.configure(text=f"Encrypt Text Saved!")
    elif 'decrypt' in folder_name.lower():
        result_text_decrypt.configure(text=f"Decrypt Text Saved!")

def action_encrypt_text(input_type, output_type, text_to_encrypt=None):
    if input_type == 'text':
        encrypted_text = encrypt_message(text_to_encrypt)
        if output_type == "text":
            result_text_encrypt.configure(text=encrypted_text)
        elif output_type == "file":
            save_file('EncryptedMessages', encrypted_text)
    elif input_type =='file':
        file_to_open = askopenfilename()
        file_to_read = open(file_to_open, 'r')
        file_content = file_to_read.read()
        file_to_read.close()
        if output_type == "text":
            encrypted_text = encrypt_message(file_content)
            result_text_encrypt.configure(text=encrypted_text)
        elif output_type == "file":
            encrypted_text = encrypt_message(file_content)
            save_file('EncryptedMessages', encrypted_text)


def action_decrypt_text(input_type, output_type, text_to_decrypt=None):
    if input_type == 'text':
        decrypted_text = decrypt_message(text_to_decrypt)
        if output_type == "text":
            result_text_decrypt.configure(text=decrypted_text)
        elif output_type == "file":
            save_file('DecryptedMessages', decrypted_text)
    elif input_type =='file':
        file_to_open = askopenfilename()
        file_to_read = open(file_to_open, 'r')
        file_content = file_to_read.read()
        file_to_read.close()
        if output_type == "text":
            decrypted_text = decrypt_message(file_content)
            result_text_decrypt.configure(text=decrypted_text)
        elif output_type == "file":
            decrypted_text = decrypt_message(file_content)
            save_file('DecryptedMessages', decrypted_text)



#Button Creations:
#Encrypt Buttons:
encrypt_text_to_text = tk.Button(left_frame, text='Encrypt Text!',
                         font=BUTTON_DESIGN,
                         bg=ENCRYPT_BUTTON_BACKGROUND,
                         command=lambda: action_encrypt_text(
                             text_to_encrypt=variable_encrypt.get(),
                             input_type='text',
                             output_type='text'
                         ))
encrypt_text_to_text.pack(side=tk.TOP, padx=10, pady = 20)

encrypt_to_file = tk.Button(left_frame, text='Encrypt Text to File!',
                            bg=ENCRYPT_BUTTON_BACKGROUND,
                            font=BUTTON_DESIGN,
                            command=lambda: action_encrypt_text(
                                text_to_encrypt=variable_encrypt.get(),
                                input_type='text',
                                output_type='file'
                            ))
encrypt_to_file.pack(side=tk.TOP, padx=10, pady = 20)

encrypt_from_file = tk.Button(left_frame, text='Encrypt from File!', font=BUTTON_DESIGN,
                              bg=ENCRYPT_BUTTON_BACKGROUND,
                              command=lambda: action_encrypt_text(
                                  input_type='file',
                                  output_type='text'
                              ))
encrypt_from_file.pack(side=tk.TOP, padx=10, pady = 20)

encrypt_from_file_to_file = tk.Button(left_frame, text='Encrypt from File to Another File',
                                      font=BUTTON_DESIGN,
                                    bg=ENCRYPT_BUTTON_BACKGROUND,
                                  command=lambda: action_encrypt_text(
                                  input_type='file',
                                  output_type='file'
                              ))
encrypt_from_file_to_file.pack(side=tk.TOP, padx=10, pady = 20)

#Decrypt Buttons:
decrypt_text = tk.Button(right_frame, text='Decrypt Text!', font=BUTTON_DESIGN,
                         bg=DECRYPT_BUTTON_BACKGROUND,
                         command=lambda: action_decrypt_text(
                             input_type='text',
                             output_type='text',
                             text_to_decrypt=variable_decrypt.get()
                         ))
decrypt_text.pack(side=tk.TOP, padx=10, pady=20)

decrypt_text_to_file = tk.Button(right_frame, text='Decrypt Text to File!', font=BUTTON_DESIGN,
                                bg=DECRYPT_BUTTON_BACKGROUND,
                                 command=lambda: action_decrypt_text(
                                     input_type='text',
                                     output_type='file',
                                     text_to_decrypt=variable_decrypt.get()
                                 ))
decrypt_text_to_file.pack(side=tk.TOP, padx=10, pady=20)

decrypt_from_file = tk.Button(right_frame,text="Decrypt from File!",font=BUTTON_DESIGN,
                              bg=DECRYPT_BUTTON_BACKGROUND,
                              command=lambda: action_decrypt_text(
                                  input_type='file',
                                  output_type='text',
                              ))
decrypt_from_file.pack(side=tk.TOP, padx=10, pady=20)

decrypt_from_file_to_file = tk.Button(right_frame,text="Decrypt from File to Another File!",font=BUTTON_DESIGN,
                                      bg=DECRYPT_BUTTON_BACKGROUND,
                                      command=lambda: action_decrypt_text(
                                          input_type='file',
                                          output_type='file'
                                      ))
decrypt_from_file_to_file.pack(side=tk.TOP, padx=10, pady=20)

root.mainloop()