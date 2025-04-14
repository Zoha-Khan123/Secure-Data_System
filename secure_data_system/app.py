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



