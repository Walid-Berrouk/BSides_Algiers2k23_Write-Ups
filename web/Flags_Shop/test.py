import re
import time

regex = r'([a-z]+)\1{50}'
string = 'abcdefghijklmnopqrstuvwxyz' * 30000

start_time = time.time()
match = re.match(regex, string)
end_time = time.time()

duration = end_time - start_time
print(f"Matching duration: {duration:.4f} seconds")
