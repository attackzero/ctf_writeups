key_map = {'04': ('a', 'A'),
           '05': ('b', 'B'),
           '06': ('c', 'C'),
           '07': ('d', 'D'),
           '08': ('e', 'E'),
           '09': ('f', 'F'),
           '0a': ('g', 'G'),
           '0b': ('h', 'H'),
           '0c': ('i', 'I'),
           '0d': ('j', 'J'),
           '0e': ('k', 'K'),
           '0f': ('l', 'L'),
           '10': ('m', 'M'),
           '11': ('n', 'N'),
           '12': ('o', 'O'),
           '13': ('p', 'P'),
           '14': ('q', 'Q'),
           '15': ('r', 'R'),
           '16': ('s', 'S'),
           '17': ('t', 'T'),
           '18': ('u', 'U'),
           '19': ('v', 'V'),
           '1a': ('w', 'W'),
           '1b': ('x', 'X'),
           '1c': ('y', 'Y'),
           '1d': ('z', 'Z'),
           '1e': ('1', '!'),
           '1f': ('2', '@'),
           '20': ('3', '#'),
           '21': ('4', '$'),
           '22': ('5', '%'),
           '23': ('6', '^'),
           '24': ('7', '&'),
           '25': ('8', '*'),
           '26': ('9', '('),
           '27': ('0', ')'),
           '28': ('\n', '\n'),
           '2c': (' ', ' '),
           '2d': ('-', '_'),
           '2e': ('=', '+'),
           '2f': ('[', '{'),
           '30': (']', '}'),
           '31': ('\\', '|'),
           '32': ('#', '~'),
           '33': (';', ':'),
           '34': ("'", '"'),
           '35': ('`', '~'),
           '36': (',', '<'),
           '37': ('.', '>'),
           '38': ('/', '?')}
with open('dev3.txt', 'r') as input_file:
    all_lines = input_file.readlines()

transcript = [[]]
current_line_index = 0

for line in all_lines:
    line = line.strip()
    line_parts = line.split(':')
    character = key_map.get(line_parts[2])
    if line_parts[2] == '00':
        continue

    if line_parts[2] == '51':
        # Down arrow
        current_line_index += 1
    elif line_parts[2] == '52':
        # Up arrow
        current_line_index -= 1
    elif line_parts[2] == '28':
        # New line
        current_line_index += 1
        transcript.append([])
    else:
        if character is None:
            print('WARNING: Could not find {} in key map'.format(line_parts[2]))
        else:
            transcript[current_line_index].append(character[0] if line_parts[0] == '00'
            else character[1])

for line in transcript:
    print(''.join(line))
 
