# import hashlib

# stored_data = {}

# print(len(stored_data))
# while True:

#     user_id = input("Enter user_id")
#     text = input("Enter text")
#     passkey = input("Enter passkey")
#     if user_id and text and passkey:
        
#         # Hash the passkey using SHA-256
#         hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()

        
#         new_data = {
#         user_id:{
#             "encrypted_text":text,
#             "passkey":hashed_passkey
#         }
#         }
        
#         stored_data.update(new_data)
#         print("Stored Data:", stored_data)

#         count = len(stored_data)
#         print(count)

#     else:
#         print("Error: All fields are required!")




                #     # Show stored data in a table format but exclude the encrypted fields
                #  # Show stored data in a table format but exclude sensitive information
                # if user_id in st.session_state.stored_data:
                #     # Prepare data for the table (excluding encrypted fields)
                #     data = st.session_state.stored_data[user_id]
                #     display_data = []
                #     for entry in data:
                #         decrypted_text = decrypt_data(entry["insert_text"])  # Decrypt the text
                #         # Only show the decrypted text, and not the passkey or encrypted text
                #         display_data.append({
                #             "Text": decrypted_text  ,# Show the decrypted text only
                #             "Passkey": "display_passkey"
                #         })

                #     # Convert the filtered data to DataFrame and display it
                #     df = pd.DataFrame(display_data)
                #     st.dataframe(df)  # Displ