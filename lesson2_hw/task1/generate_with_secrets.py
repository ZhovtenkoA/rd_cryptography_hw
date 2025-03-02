import secrets



def generate_random_numbers(filename, size_in_gb):
    num_bytes = size_in_gb * 1024 * 1024 * 1024  
    with open(filename, 'wb') as f:
        while num_bytes > 0:
            random_number = secrets.randbits(32)  
            f.write(random_number.to_bytes(4, byteorder='big')) 
            num_bytes -= 4



print("Starting....")
generate_random_numbers('secrets.bin', 1)  
print("....the end.")