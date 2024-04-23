# animation.py

import threading
import sys
import time

stop_animation = threading.Event()
animation_thread = None

def loading_animation(execution_type):
    message = "Executing TestSSL..." if execution_type == "testssl" else "Executing FFUF..."
    animation = "|/-\\"
    i = 0
    while not stop_animation.is_set():
        sys.stdout.write("\r" + animation[i % len(animation)] + "    " + message)
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1

def start_loading_animation(execution_type):
    global animation_thread
    stop_animation.clear()  # Reset the stop flag
    animation_thread = threading.Thread(target=loading_animation, args=(execution_type,))
    print()
    animation_thread.start()

def stop_loading_animation():
    stop_animation.set()
    animation_thread.join()
